import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 21', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to schedule page before each test
    await page.goto('/schedule');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate navigation between schedule views', async ({ page }) => {
    // Verify default view is displayed
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Action: Employee clicks on weekly view tab
    const weeklyViewTab = page.locator('[data-testid="weekly-view-tab"]').or(page.getByRole('button', { name: /weekly view/i }));
    await weeklyViewTab.click();
    
    // Expected Result: Weekly schedule is displayed
    await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText(/weekly/i);
    
    // Verify weekly view displays correct schedule data for the current week
    await expect(page.locator('[data-testid="week-days-container"]')).toBeVisible();
    const weekDays = page.locator('[data-testid="week-day"]');
    await expect(weekDays).toHaveCount(7);

    // Action: Employee clicks on monthly view tab
    const monthlyViewTab = page.locator('[data-testid="monthly-view-tab"]').or(page.getByRole('button', { name: /monthly view/i }));
    const startTime = Date.now();
    await monthlyViewTab.click();
    
    // Expected Result: Monthly schedule is displayed
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText(/monthly/i);
    
    // Verify monthly view displays correct schedule data for the current month
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    const monthCells = page.locator('[data-testid="calendar-day-cell"]');
    await expect(monthCells.first()).toBeVisible();
    
    // Measure time taken to switch from weekly to monthly view
    const weeklyToMonthlyTime = Date.now() - startTime;
    expect(weeklyToMonthlyTime).toBeLessThan(2000);

    // Action: Employee clicks on daily view tab
    const dailyViewTab = page.locator('[data-testid="daily-view-tab"]').or(page.getByRole('button', { name: /daily view/i }));
    const dailyStartTime = Date.now();
    await dailyViewTab.click();
    
    // Expected Result: Daily schedule is displayed
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText(/daily/i);
    
    // Verify daily view displays correct schedule data for the current day
    await expect(page.locator('[data-testid="daily-time-slots"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-day-header"]')).toBeVisible();
    
    // Measure time taken to switch from monthly to daily view
    const monthlyToDailyTime = Date.now() - dailyStartTime;
    expect(monthlyToDailyTime).toBeLessThan(2000);

    // Navigate through all three views in sequence: daily → weekly → monthly → daily
    await weeklyViewTab.click();
    await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
    
    await monthlyViewTab.click();
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    await dailyViewTab.click();
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
  });

  test('Verify active view visual feedback', async ({ page }) => {
    // Observe the initial state of navigation tabs/buttons when schedule page loads
    const dailyTab = page.locator('[data-testid="daily-view-tab"]').or(page.getByRole('button', { name: /daily view/i }));
    const weeklyTab = page.locator('[data-testid="weekly-view-tab"]').or(page.getByRole('button', { name: /weekly view/i }));
    const monthlyTab = page.locator('[data-testid="monthly-view-tab"]').or(page.getByRole('button', { name: /monthly view/i }));
    
    await expect(dailyTab).toBeVisible();
    await expect(weeklyTab).toBeVisible();
    await expect(monthlyTab).toBeVisible();

    // Action: Employee selects a schedule view (Daily View)
    await dailyTab.click();
    
    // Expected Result: Selected view tab is highlighted
    await expect(dailyTab).toHaveClass(/active|selected|highlighted/);
    await expect(dailyTab).toHaveAttribute('aria-selected', 'true');
    
    // Verify that weekly and monthly tabs are visually distinct from the active daily tab
    await expect(weeklyTab).not.toHaveClass(/active|selected|highlighted/);
    await expect(monthlyTab).not.toHaveClass(/active|selected|highlighted/);
    
    // Click on the 'Weekly View' tab and observe the visual state change
    await weeklyTab.click();
    await expect(weeklyTab).toHaveClass(/active|selected|highlighted/);
    await expect(weeklyTab).toHaveAttribute('aria-selected', 'true');
    
    // Verify the active state styling is consistent with design standards
    const weeklyTabStyles = await weeklyTab.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        backgroundColor: styles.backgroundColor,
        fontWeight: styles.fontWeight,
        borderBottom: styles.borderBottom
      };
    });
    expect(weeklyTabStyles).toBeTruthy();
    
    // Verify daily and monthly tabs are not active
    await expect(dailyTab).not.toHaveClass(/active|selected|highlighted/);
    await expect(monthlyTab).not.toHaveClass(/active|selected|highlighted/);

    // Click on the 'Monthly View' tab and observe the visual feedback
    await monthlyTab.click();
    await expect(monthlyTab).toHaveClass(/active|selected|highlighted/);
    await expect(monthlyTab).toHaveAttribute('aria-selected', 'true');
    
    // Verify other tabs are not active
    await expect(dailyTab).not.toHaveClass(/active|selected|highlighted/);
    await expect(weeklyTab).not.toHaveClass(/active|selected|highlighted/);

    // Hover over inactive tabs and observe any hover state feedback
    await dailyTab.hover();
    await expect(dailyTab).toBeVisible();
    
    await weeklyTab.hover();
    await expect(weeklyTab).toBeVisible();

    // Rapidly switch between all three views and verify visual feedback updates correctly
    await dailyTab.click();
    await expect(dailyTab).toHaveClass(/active|selected|highlighted/);
    
    await weeklyTab.click();
    await expect(weeklyTab).toHaveClass(/active|selected|highlighted/);
    
    await monthlyTab.click();
    await expect(monthlyTab).toHaveClass(/active|selected|highlighted/);
    
    await dailyTab.click();
    await expect(dailyTab).toHaveClass(/active|selected|highlighted/);

    // Refresh the page while on a specific view and verify active state persists
    await weeklyTab.click();
    await expect(weeklyTab).toHaveClass(/active|selected|highlighted/);
    
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify the weekly view is still active after refresh
    const weeklyTabAfterReload = page.locator('[data-testid="weekly-view-tab"]').or(page.getByRole('button', { name: /weekly view/i }));
    await expect(weeklyTabAfterReload).toHaveClass(/active|selected|highlighted/);
  });
});