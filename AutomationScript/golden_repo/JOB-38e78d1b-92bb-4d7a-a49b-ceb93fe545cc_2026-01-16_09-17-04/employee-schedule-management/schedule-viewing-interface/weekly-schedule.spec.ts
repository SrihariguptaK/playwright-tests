import { test, expect } from '@playwright/test';

test.describe('Weekly Schedule View - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'Password123!';

  test('Validate weekly schedule display with accurate shift data', async ({ page }) => {
    // Navigate to the web portal and log in with valid employee credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to the schedule section from the main menu
    await page.click('[data-testid="schedule-menu"]');
    
    // Select the weekly schedule view option
    await page.click('[data-testid="weekly-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Verify the week date range is displayed in the header
    const weekHeader = page.locator('[data-testid="week-header"]');
    await expect(weekHeader).toBeVisible();
    await expect(weekHeader).toContainText(/Week of|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec/);
    
    // Verify all seven days of the week are displayed
    const dayColumns = page.locator('[data-testid="day-column"]');
    await expect(dayColumns).toHaveCount(7);
    
    // Verify days are labeled correctly
    const dayLabels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    for (const day of dayLabels) {
      await expect(page.locator(`text=${day}`).first()).toBeVisible();
    }
    
    // Review each scheduled shift and verify shift start time is displayed correctly
    const shifts = page.locator('[data-testid="shift-card"]');
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    for (let i = 0; i < Math.min(shiftCount, 3); i++) {
      const shift = shifts.nth(i);
      await expect(shift.locator('[data-testid="shift-start-time"]')).toBeVisible();
      await expect(shift.locator('[data-testid="shift-start-time"]')).toContainText(/\d{1,2}:\d{2}|AM|PM/);
      
      // Verify shift end time is displayed correctly
      await expect(shift.locator('[data-testid="shift-end-time"]')).toBeVisible();
      await expect(shift.locator('[data-testid="shift-end-time"]')).toContainText(/\d{1,2}:\d{2}|AM|PM/);
      
      // Verify location information is displayed for each shift
      await expect(shift.locator('[data-testid="shift-location"]')).toBeVisible();
      
      // Verify role information is displayed for each shift
      await expect(shift.locator('[data-testid="shift-role"]')).toBeVisible();
    }
    
    // Click the previous week navigation button
    await page.click('[data-testid="previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(weekHeader).toBeVisible();
    
    // Click the next week navigation button twice
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    await page.click('[data-testid="next-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Return to current week view
    await page.click('[data-testid="current-week-button"]');
    await page.waitForLoadState('networkidle');
    
    // Test responsive design by resizing browser to tablet dimensions
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(weekHeader).toBeVisible();
    await expect(dayColumns.first()).toBeVisible();
    
    // Test responsive design by resizing browser to mobile dimensions
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(weekHeader).toBeVisible();
    
    // Reset viewport
    await page.setViewportSize({ width: 1280, height: 720 });
  });

  test('Verify weekend and holiday highlighting in weekly view', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to the weekly schedule view
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="weekly-view-option"]');
    await page.waitForLoadState('networkidle');
    
    // Identify Saturday in the weekly schedule display
    const saturdayColumn = page.locator('[data-testid="day-column"]').filter({ hasText: 'Saturday' });
    await expect(saturdayColumn).toBeVisible();
    
    // Verify Saturday has visual distinction (different background color, border, or styling)
    const saturdayClass = await saturdayColumn.getAttribute('class');
    expect(saturdayClass).toMatch(/weekend|saturday|highlight/i);
    
    // Identify Sunday in the weekly schedule display
    const sundayColumn = page.locator('[data-testid="day-column"]').filter({ hasText: 'Sunday' });
    await expect(sundayColumn).toBeVisible();
    
    // Verify Sunday has visual distinction (different background color, border, or styling)
    const sundayClass = await sundayColumn.getAttribute('class');
    expect(sundayClass).toMatch(/weekend|sunday|highlight/i);
    
    // Navigate to a week that contains a company holiday using the week navigation controls
    // Assuming we need to navigate forward to find a holiday
    let holidayFound = false;
    for (let i = 0; i < 8; i++) {
      const holidayIndicator = page.locator('[data-testid="holiday-indicator"]');
      const count = await holidayIndicator.count();
      if (count > 0) {
        holidayFound = true;
        break;
      }
      await page.click('[data-testid="next-week-button"]');
      await page.waitForLoadState('networkidle');
    }
    
    if (holidayFound) {
      // Identify the company holiday date in the weekly schedule
      const holidayDay = page.locator('[data-testid="holiday-day"]').first();
      await expect(holidayDay).toBeVisible();
      
      // Verify the holiday has distinct visual highlighting
      const holidayClass = await holidayDay.getAttribute('class');
      expect(holidayClass).toMatch(/holiday|special/i);
      
      // Verify holiday name or description is displayed if applicable
      const holidayLabel = page.locator('[data-testid="holiday-label"]').first();
      await expect(holidayLabel).toBeVisible();
    }
    
    // Compare the visual styling of weekends versus holidays versus regular weekdays
    const regularWeekday = page.locator('[data-testid="day-column"]').filter({ hasText: 'Monday' });
    const regularClass = await regularWeekday.getAttribute('class');
    expect(regularClass).not.toMatch(/weekend|holiday/i);
    
    // Test highlighting visibility on mobile view
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(saturdayColumn).toBeVisible();
    await expect(sundayColumn).toBeVisible();
    
    // Reset viewport
    await page.setViewportSize({ width: 1280, height: 720 });
  });

  test('Test access restriction for unauthenticated users', async ({ page }) => {
    // Open a new browser context to ensure no active session exists
    await page.context().clearCookies();
    
    // Attempt to directly access the weekly schedule URL
    await page.goto(`${BASE_URL}/schedules/weekly`);
    
    // Verify automatic redirect to the login page occurs
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Verify an appropriate authentication error message or prompt is displayed
    const authMessage = page.locator('[data-testid="auth-message"]');
    if (await authMessage.isVisible()) {
      await expect(authMessage).toContainText(/login|authenticate|sign in/i);
    }
    
    // Verify the login page displays username and password fields
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    
    // Enter valid employee credentials in the login form
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    
    // Submit the login form by clicking the Login button
    await page.click('[data-testid="login-button"]');
    
    // Verify redirect to weekly schedule page or dashboard occurs after successful login
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to the weekly schedule view if not automatically redirected
    const currentUrl = page.url();
    if (!currentUrl.includes('weekly')) {
      await page.click('[data-testid="schedule-menu"]');
      await page.click('[data-testid="weekly-view-option"]');
    }
    
    // Verify all weekly schedule features are functional
    await page.waitForLoadState('networkidle');
    
    // Verify navigation works
    const previousButton = page.locator('[data-testid="previous-week-button"]');
    await expect(previousButton).toBeVisible();
    await expect(previousButton).toBeEnabled();
    
    const nextButton = page.locator('[data-testid="next-week-button"]');
    await expect(nextButton).toBeVisible();
    await expect(nextButton).toBeEnabled();
    
    // Verify data display
    const weekHeader = page.locator('[data-testid="week-header"]');
    await expect(weekHeader).toBeVisible();
    
    const dayColumns = page.locator('[data-testid="day-column"]');
    await expect(dayColumns.first()).toBeVisible();
  });
});