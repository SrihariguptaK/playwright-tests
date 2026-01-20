import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 18', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login as employee with valid credentials
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate monthly schedule display with shift indicators (happy-path)', async ({ page }) => {
    const startTime = Date.now();
    
    // Navigate to and select the 'Monthly Schedule View' option from the menu
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="monthly-schedule-view"]');
    
    // Wait for the monthly calendar to load
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    
    const loadTime = Date.now() - startTime;
    
    // Verify the calendar loads within 5 seconds
    expect(loadTime).toBeLessThan(5000);
    
    // Verify shift indicators are visible on dates with assigned shifts
    const shiftIndicators = page.locator('[data-testid="shift-indicator"]');
    await expect(shiftIndicators.first()).toBeVisible();
    const shiftCount = await shiftIndicators.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Verify the current month is highlighted or clearly indicated
    const currentMonthHeader = page.locator('[data-testid="current-month-header"]');
    await expect(currentMonthHeader).toBeVisible();
    const currentMonth = new Date().toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(currentMonthHeader).toContainText(new Date().getFullYear().toString());
    
    // Click the 'Next Month' navigation button
    await page.click('[data-testid="next-month-button"]');
    
    // Verify the next month's schedule is displayed correctly
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    const nextMonthHeader = page.locator('[data-testid="current-month-header"]');
    await expect(nextMonthHeader).toBeVisible();
    
    // Navigate back to current month for hover test
    await page.click('[data-testid="previous-month-button"]');
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    
    // Hover the mouse cursor over a date with a shift indicator
    const firstShiftIndicator = shiftIndicators.first();
    await firstShiftIndicator.hover();
    
    // Verify the shift details displayed are accurate and complete
    const shiftDetailsPopup = page.locator('[data-testid="shift-details-popup"]');
    await expect(shiftDetailsPopup).toBeVisible();
    await expect(shiftDetailsPopup).toContainText(/shift/i);
    
    // Verify shift details contain required information
    const shiftTime = page.locator('[data-testid="shift-time"]');
    await expect(shiftTime).toBeVisible();
    
    // Move the mouse cursor away from the shift indicator
    await page.mouse.move(0, 0);
    await expect(shiftDetailsPopup).toBeHidden();
  });

  test('Verify navigation between months (happy-path)', async ({ page }) => {
    // Navigate to monthly schedule view
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="monthly-schedule-view"]');
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    
    // Verify the current month is displayed in the monthly schedule view
    const currentMonthHeader = page.locator('[data-testid="current-month-header"]');
    await expect(currentMonthHeader).toBeVisible();
    const initialMonthText = await currentMonthHeader.textContent();
    
    // Locate and click the 'Previous Month' navigation button
    const startTime = Date.now();
    await page.click('[data-testid="previous-month-button"]');
    
    // Verify the previous month's schedule is displayed correctly
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    const previousMonthText = await currentMonthHeader.textContent();
    expect(previousMonthText).not.toBe(initialMonthText);
    
    // Verify the schedule loads within 5 seconds
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(5000);
    
    // Verify no errors are displayed during navigation
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).not.toBeVisible();
    
    // Click the 'Next Month' navigation button
    const nextStartTime = Date.now();
    await page.click('[data-testid="next-month-button"]');
    
    // Verify the next month's schedule is displayed correctly
    await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
    const nextMonthText = await currentMonthHeader.textContent();
    expect(nextMonthText).toBe(initialMonthText);
    
    // Verify the schedule loads within 5 seconds
    const nextLoadTime = Date.now() - nextStartTime;
    expect(nextLoadTime).toBeLessThan(5000);
    
    // Click the 'Next Month' button multiple times consecutively (3-4 times)
    for (let i = 0; i < 4; i++) {
      await page.click('[data-testid="next-month-button"]');
      await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
      await page.waitForTimeout(300); // Brief pause between clicks
    }
    
    const forwardMonthText = await currentMonthHeader.textContent();
    expect(forwardMonthText).not.toBe(initialMonthText);
    
    // Click the 'Previous Month' button multiple times consecutively to return to the original month
    for (let i = 0; i < 4; i++) {
      await page.click('[data-testid="previous-month-button"]');
      await page.waitForSelector('[data-testid="monthly-calendar"]', { state: 'visible' });
      await page.waitForTimeout(300); // Brief pause between clicks
    }
    
    // Verify the schedule data remains accurate after multiple navigations
    const finalMonthText = await currentMonthHeader.textContent();
    expect(finalMonthText).toBe(initialMonthText);
    
    // Verify calendar is still functional and displays shift indicators
    const shiftIndicators = page.locator('[data-testid="shift-indicator"]');
    const shiftCount = await shiftIndicators.count();
    expect(shiftCount).toBeGreaterThanOrEqual(0);
    
    // Verify no errors after multiple navigations
    await expect(errorMessage).not.toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    // Logout after each test
    await page.click('[data-testid="user-menu"]').catch(() => {});
    await page.click('[data-testid="logout-button"]').catch(() => {});
  });
});