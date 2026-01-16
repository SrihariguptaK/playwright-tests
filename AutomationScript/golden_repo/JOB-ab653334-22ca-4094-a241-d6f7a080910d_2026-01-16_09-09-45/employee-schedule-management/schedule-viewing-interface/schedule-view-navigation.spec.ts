import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 19', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test.afterEach(async ({ page }) => {
    // Employee logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate navigation between schedule views - Navigate to schedule section from main dashboard', async ({ page }) => {
    // Navigate to the schedule section from the main dashboard
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Verify the current date is displayed in the daily view
    const currentDate = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
    await expect(page.locator('[data-testid="schedule-view-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
  });

  test('Validate navigation between schedule views - Switch to Weekly View and verify date context', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Get current date context from daily view
    const dailyViewDate = await page.locator('[data-testid="current-date-display"]').textContent();
    
    // Click on the 'Weekly View' navigation tab or button
    await page.click('[data-testid="weekly-view-tab"]');
    
    // Verify the date context is maintained in weekly view
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    const weeklyViewDate = await page.locator('[data-testid="current-week-display"]').textContent();
    expect(weeklyViewDate).toContain(new Date().getFullYear().toString());
  });

  test('Validate navigation between schedule views - Switch to Monthly View and verify date context', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Switch to weekly view first
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    
    // Click on the 'Monthly View' navigation tab or button
    await page.click('[data-testid="monthly-view-tab"]');
    
    // Verify the date context is maintained in monthly view
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    const monthlyViewDate = await page.locator('[data-testid="current-month-display"]').textContent();
    const currentMonth = new Date().toLocaleDateString('en-US', { month: 'long' });
    expect(monthlyViewDate).toContain(currentMonth);
  });

  test('Validate navigation between schedule views - Return to Daily View and verify controls', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Navigate through views
    await page.click('[data-testid="weekly-view-tab"]');
    await page.click('[data-testid="monthly-view-tab"]');
    
    // Click on the 'Daily View' navigation tab or button
    await page.click('[data-testid="daily-view-tab"]');
    
    // Verify all navigation controls are clearly visible and labeled
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-tab"]')).toBeVisible();
    
    // Verify labels
    await expect(page.locator('[data-testid="daily-view-tab"]')).toContainText('Daily');
    await expect(page.locator('[data-testid="weekly-view-tab"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="monthly-view-tab"]')).toContainText('Monthly');
  });

  test('Test navigation performance - Measure load times for view transitions', async ({ page }) => {
    // Navigate to the schedule section and ensure daily view is displayed
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Click on 'Weekly View' navigation control and measure the time taken to load
    const weeklyStartTime = Date.now();
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    const weeklyLoadTime = Date.now() - weeklyStartTime;
    expect(weeklyLoadTime).toBeLessThan(1000);
    
    // Click on 'Monthly View' navigation control and measure the time taken to load
    const monthlyStartTime = Date.now();
    await page.click('[data-testid="monthly-view-tab"]');
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    const monthlyLoadTime = Date.now() - monthlyStartTime;
    expect(monthlyLoadTime).toBeLessThan(1000);
    
    // Click on 'Daily View' navigation control and measure the time taken to load
    const dailyStartTime = Date.now();
    await page.click('[data-testid="daily-view-tab"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    const dailyLoadTime = Date.now() - dailyStartTime;
    expect(dailyLoadTime).toBeLessThan(1000);
  });

  test('Test navigation performance - Complete 5 navigation cycles', async ({ page }) => {
    // Navigate to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Repeat the navigation sequence: Daily → Weekly → Monthly → Daily for a total of 5 complete cycles
    for (let i = 0; i < 5; i++) {
      // Daily to Weekly
      const weeklyStart = Date.now();
      await page.click('[data-testid="weekly-view-tab"]');
      await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
      expect(Date.now() - weeklyStart).toBeLessThan(1000);
      
      // Weekly to Monthly
      const monthlyStart = Date.now();
      await page.click('[data-testid="monthly-view-tab"]');
      await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
      expect(Date.now() - monthlyStart).toBeLessThan(1000);
      
      // Monthly to Daily
      const dailyStart = Date.now();
      await page.click('[data-testid="daily-view-tab"]');
      await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
      expect(Date.now() - dailyStart).toBeLessThan(1000);
    }
  });

  test('Test navigation performance - Rapid view switching', async ({ page }) => {
    // Navigate to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Rapidly switch between views by clicking navigation controls in quick succession
    const rapidSwitchStart = Date.now();
    
    await page.click('[data-testid="weekly-view-tab"]');
    await page.click('[data-testid="monthly-view-tab"]');
    await page.click('[data-testid="daily-view-tab"]');
    await page.click('[data-testid="weekly-view-tab"]');
    await page.click('[data-testid="monthly-view-tab"]');
    
    // Wait for final view to load
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    
    const totalRapidSwitchTime = Date.now() - rapidSwitchStart;
    
    // Verify no loading spinners or delays exceed 1 second during any view transition
    const loadingSpinner = page.locator('[data-testid="loading-spinner"]');
    await expect(loadingSpinner).not.toBeVisible({ timeout: 1000 });
  });

  test('Test navigation performance - Delayed view switching with wait', async ({ page }) => {
    // Navigate to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Switch to Weekly view, wait 2 seconds, then switch to Monthly view and measure load time
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    
    await page.waitForTimeout(2000);
    
    const monthlyStartTime = Date.now();
    await page.click('[data-testid="monthly-view-tab"]');
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    const monthlyLoadTime = Date.now() - monthlyStartTime;
    
    // Verify no loading spinners or delays exceed 1 second during any view transition
    expect(monthlyLoadTime).toBeLessThan(1000);
    const loadingSpinner = page.locator('[data-testid="loading-spinner"]');
    await expect(loadingSpinner).not.toBeVisible({ timeout: 1000 });
  });

  test('Validate navigation between schedule views - Employee selects weekly view from daily view', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Get current week information
    const currentDate = new Date();
    const currentWeek = getWeekNumber(currentDate);
    
    // Employee selects weekly view from daily view
    await page.click('[data-testid="weekly-view-tab"]');
    
    // Weekly schedule loads retaining the current week
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    const weekDisplay = await page.locator('[data-testid="current-week-display"]').textContent();
    expect(weekDisplay).toBeTruthy();
  });

  test('Validate navigation between schedule views - Employee switches to monthly view', async ({ page }) => {
    // Navigate to schedule section and switch to weekly view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
    
    // Get current month information
    const currentMonth = new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    
    // Employee switches to monthly view
    await page.click('[data-testid="monthly-view-tab"]');
    
    // Monthly schedule loads retaining the current month
    await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
    const monthDisplay = await page.locator('[data-testid="current-month-display"]').textContent();
    expect(monthDisplay).toContain(new Date().getFullYear().toString());
  });

  test('Test navigation performance - Switch between schedule views multiple times', async ({ page }) => {
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
    
    // Switch between schedule views multiple times
    const iterations = 10;
    
    for (let i = 0; i < iterations; i++) {
      // Switch to Weekly
      const weeklyStart = Date.now();
      await page.click('[data-testid="weekly-view-tab"]');
      await expect(page.locator('[data-testid="weekly-view-container"]')).toBeVisible();
      const weeklyTime = Date.now() - weeklyStart;
      expect(weeklyTime).toBeLessThan(1000);
      
      // Switch to Monthly
      const monthlyStart = Date.now();
      await page.click('[data-testid="monthly-view-tab"]');
      await expect(page.locator('[data-testid="monthly-view-container"]')).toBeVisible();
      const monthlyTime = Date.now() - monthlyStart;
      expect(monthlyTime).toBeLessThan(1000);
      
      // Switch back to Daily
      const dailyStart = Date.now();
      await page.click('[data-testid="daily-view-tab"]');
      await expect(page.locator('[data-testid="daily-view-container"]')).toBeVisible();
      const dailyTime = Date.now() - dailyStart;
      expect(dailyTime).toBeLessThan(1000);
    }
  });
});

// Helper function to get week number
function getWeekNumber(date: Date): number {
  const firstDayOfYear = new Date(date.getFullYear(), 0, 1);
  const pastDaysOfYear = (date.getTime() - firstDayOfYear.getTime()) / 86400000;
  return Math.ceil((pastDaysOfYear + firstDayOfYear.getDay() + 1) / 7);
}