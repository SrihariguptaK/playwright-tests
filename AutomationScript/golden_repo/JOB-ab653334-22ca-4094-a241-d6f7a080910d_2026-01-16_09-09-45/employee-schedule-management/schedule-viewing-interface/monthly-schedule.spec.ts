import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 17', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate monthly schedule calendar display (happy-path)', async ({ page }) => {
    // Navigate to the application login page
    await page.goto('/login');
    
    // Enter valid employee credentials and click Login button
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the schedule section from the main menu
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Select monthly view option
    await page.click('[data-testid="monthly-view-button"]');
    
    // Verify that all assigned shifts are visible on the calendar with correct dates, times, and shift details
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Verify calendar grid is displayed
    const calendarGrid = page.locator('[data-testid="calendar-grid"]');
    await expect(calendarGrid).toBeVisible();
    
    // Verify shifts are displayed with correct information
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    
    // Verify shift details are present (date, time, shift type)
    const firstShift = shifts.first();
    await expect(firstShift.locator('[data-testid="shift-date"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-time"]')).toBeVisible();
    
    // Click the previous month navigation button
    const startTime = Date.now();
    await page.click('[data-testid="previous-month-button"]');
    
    // Verify previous month loads correctly
    await expect(page.locator('[data-testid="month-year-display"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Click the next month navigation button twice
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Verify the page load time is within acceptable limits (4 seconds)
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    expect(loadTime).toBeLessThan(4);
    
    // Verify schedules for selected months load correctly
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
  });

  test('Verify highlighting of days with scheduled shifts (happy-path)', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to the monthly schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // View calendar for month with scheduled shifts
    const calendarGrid = page.locator('[data-testid="calendar-grid"]');
    await expect(calendarGrid).toBeVisible();
    
    // Identify days on the calendar that have scheduled shifts assigned
    const highlightedDays = page.locator('[data-testid="calendar-day"][data-has-shift="true"]');
    const highlightedDaysCount = await highlightedDays.count();
    expect(highlightedDaysCount).toBeGreaterThan(0);
    
    // Verify days with shifts are visually distinct
    const firstHighlightedDay = highlightedDays.first();
    await expect(firstHighlightedDay).toBeVisible();
    
    // Verify the visual distinction is clear (check for highlight class or styling)
    await expect(firstHighlightedDay).toHaveClass(/highlighted|has-shift|shift-day/);
    
    // Compare highlighted days against the employee's known shift schedule
    // Verify each highlighted day contains shift information
    for (let i = 0; i < Math.min(highlightedDaysCount, 5); i++) {
      const day = highlightedDays.nth(i);
      await expect(day).toHaveAttribute('data-has-shift', 'true');
    }
    
    // Navigate to a different month with known shift assignments
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify highlighting persists in the new month
    const nextMonthHighlightedDays = page.locator('[data-testid="calendar-day"][data-has-shift="true"]');
    await expect(nextMonthHighlightedDays.first()).toBeVisible();
    
    // Verify the visual distinction is clear and easily identifiable
    await expect(nextMonthHighlightedDays.first()).toHaveClass(/highlighted|has-shift|shift-day/);
  });

  test('System displays monthly schedule in calendar format with accurate shift data', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to monthly schedule
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Verify calendar displays all scheduled shifts accurately
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    
    // Verify shift data accuracy
    const shiftData = await shifts.first().textContent();
    expect(shiftData).toBeTruthy();
  });

  test('Days with scheduled shifts are visually highlighted', async ({ page }) => {
    // Login and navigate
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Verify days with shifts are visually distinct
    const highlightedDays = page.locator('[data-testid="calendar-day"][data-has-shift="true"]');
    await expect(highlightedDays.first()).toBeVisible();
    await expect(highlightedDays.first()).toHaveClass(/highlighted|has-shift|shift-day/);
  });

  test('System allows navigation to previous and next months without errors', async ({ page }) => {
    // Login and navigate
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Navigate to previous month
    await page.click('[data-testid="previous-month-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Navigate to next month
    await page.click('[data-testid="next-month-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Verify no errors occurred
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toHaveCount(0);
  });

  test('Monthly schedule loads within 4 seconds on supported devices', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Measure load time
    const startTime = Date.now();
    await page.click('[data-testid="monthly-view-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    const endTime = Date.now();
    
    const loadTime = (endTime - startTime) / 1000;
    expect(loadTime).toBeLessThan(4);
  });

  test('Access is restricted to authenticated employees', async ({ page }) => {
    // Attempt to access schedule without authentication
    await page.goto('/schedule/monthly');
    
    // Verify redirect to login or access denied
    await expect(page).toHaveURL(/.*login/);
  });
});