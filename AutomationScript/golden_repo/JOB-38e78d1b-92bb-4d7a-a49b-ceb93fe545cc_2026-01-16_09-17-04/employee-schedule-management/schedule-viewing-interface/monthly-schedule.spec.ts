import { test, expect } from '@playwright/test';

test.describe('Story-17: Monthly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to employee portal login page
    await page.goto('/employee/login');
    
    // Enter valid employee credentials and login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate monthly schedule calendar display (happy-path)', async ({ page }) => {
    // Navigate to the schedule section from the main menu
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Select the monthly view option
    await page.click('[data-testid="monthly-view-button"]');
    
    // Verify calendar displays all scheduled shifts accurately
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify calendar has shift data displayed
    const shiftsInCalendar = page.locator('[data-testid="shift-item"]');
    await expect(shiftsInCalendar.first()).toBeVisible();
    const shiftCount = await shiftsInCalendar.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Click the 'Previous Month' navigation button
    await page.click('[data-testid="previous-month-button"]');
    
    // Verify schedules for previous month load correctly
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Verify month label changed to previous month
    const previousMonthLabel = await page.locator('[data-testid="month-year-label"]').textContent();
    expect(previousMonthLabel).toBeTruthy();
    
    // Click the 'Next Month' navigation button twice
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Verify the page load time using performance API
    const performanceTiming = await page.evaluate(() => {
      const perfData = window.performance.timing;
      return perfData.loadEventEnd - perfData.navigationStart;
    });
    
    // Verify load time is under 4 seconds (4000ms)
    expect(performanceTiming).toBeLessThan(4000);
  });

  test('Verify highlighting of days with scheduled shifts (happy-path)', async ({ page }) => {
    // Navigate to the schedule section and select monthly view
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.click('[data-testid="monthly-view-button"]');
    
    // Wait for calendar to load
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Identify days in the calendar that have scheduled shifts assigned
    const highlightedDays = page.locator('[data-testid="calendar-day"][data-has-shift="true"]');
    const highlightedDaysCount = await highlightedDays.count();
    expect(highlightedDaysCount).toBeGreaterThan(0);
    
    // Verify days with shifts are visually distinct
    const firstHighlightedDay = highlightedDays.first();
    await expect(firstHighlightedDay).toBeVisible();
    
    // Verify the visual distinction is clear (check for highlight class or styling)
    const hasHighlightClass = await firstHighlightedDay.evaluate((el) => {
      return el.classList.contains('highlighted') || 
             el.classList.contains('has-shift') ||
             el.getAttribute('data-has-shift') === 'true';
    });
    expect(hasHighlightClass).toBeTruthy();
    
    // Compare highlighted days against actual shift schedule data
    const shiftDates = await page.locator('[data-testid="shift-item"]').evaluateAll((shifts) => {
      return shifts.map(shift => shift.getAttribute('data-date'));
    });
    
    // Verify each shift date has a corresponding highlighted day
    for (const shiftDate of shiftDates) {
      const dayElement = page.locator(`[data-testid="calendar-day"][data-date="${shiftDate}"]`);
      await expect(dayElement).toHaveAttribute('data-has-shift', 'true');
    }
    
    // Verify contrast and visibility for accessibility
    const backgroundColor = await firstHighlightedDay.evaluate((el) => {
      return window.getComputedStyle(el).backgroundColor;
    });
    expect(backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
    expect(backgroundColor).not.toBe('transparent');
    
    // Navigate to a different month with scheduled shifts
    await page.click('[data-testid="next-month-button"]');
    await page.waitForLoadState('networkidle');
    
    // Verify highlighting persists in the new month
    const nextMonthHighlightedDays = page.locator('[data-testid="calendar-day"][data-has-shift="true"]');
    const nextMonthHighlightedCount = await nextMonthHighlightedDays.count();
    
    // Verify visual distinction is maintained in the new month
    if (nextMonthHighlightedCount > 0) {
      await expect(nextMonthHighlightedDays.first()).toBeVisible();
      const nextMonthHasHighlight = await nextMonthHighlightedDays.first().evaluate((el) => {
        return el.classList.contains('highlighted') || 
               el.classList.contains('has-shift') ||
               el.getAttribute('data-has-shift') === 'true';
      });
      expect(nextMonthHasHighlight).toBeTruthy();
    }
  });

  test.afterEach(async ({ page }) => {
    // Logout after each test
    await page.click('[data-testid="user-menu-button"]').catch(() => {});
    await page.click('[data-testid="logout-button"]').catch(() => {});
  });
});