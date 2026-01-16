import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 19', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test.afterEach(async ({ page }) => {
    // Employee logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate navigation between schedule views', async ({ page }) => {
    // Note the current date displayed in the daily view
    await expect(page.locator('[data-testid="daily-view"]')).toBeVisible();
    const dailyDateText = await page.locator('[data-testid="current-date-display"]').textContent();
    const currentDate = new Date(dailyDateText || '');
    
    // Action: Employee selects weekly view from daily view
    await page.click('[data-testid="weekly-view-tab"]');
    
    // Expected Result: Weekly schedule loads retaining the current week
    await expect(page.locator('[data-testid="weekly-view"]')).toBeVisible();
    const weeklyDateRange = await page.locator('[data-testid="date-range-display"]').textContent();
    expect(weeklyDateRange).toBeTruthy();
    
    // Verify that the week displayed contains the date from the daily view
    const weekStartDate = await page.locator('[data-testid="week-start-date"]').getAttribute('data-date');
    const weekEndDate = await page.locator('[data-testid="week-end-date"]').getAttribute('data-date');
    expect(new Date(weekStartDate || '')).toBeLessThanOrEqual(currentDate);
    expect(new Date(weekEndDate || '')).toBeGreaterThanOrEqual(currentDate);
    
    // Action: Employee switches to monthly view
    await page.click('[data-testid="monthly-view-tab"]');
    
    // Expected Result: Monthly schedule loads retaining the current month
    await expect(page.locator('[data-testid="monthly-view"]')).toBeVisible();
    const monthlyDateDisplay = await page.locator('[data-testid="month-year-display"]').textContent();
    expect(monthlyDateDisplay).toBeTruthy();
    
    // Verify that the month displayed contains the date from the previous views
    const displayedMonth = await page.locator('[data-testid="current-month"]').getAttribute('data-month');
    const displayedYear = await page.locator('[data-testid="current-year"]').getAttribute('data-year');
    expect(parseInt(displayedMonth || '0')).toBe(currentDate.getMonth() + 1);
    expect(parseInt(displayedYear || '0')).toBe(currentDate.getFullYear());
    
    // Click on the 'Daily View' navigation tab or button
    await page.click('[data-testid="daily-view-tab"]');
    await expect(page.locator('[data-testid="daily-view"]')).toBeVisible();
    
    // Verify date context is maintained
    const finalDailyDate = await page.locator('[data-testid="current-date-display"]').textContent();
    expect(finalDailyDate).toBe(dailyDateText);
  });

  test('Test navigation performance', async ({ page }) => {
    // Navigate to the schedule section and ensure daily view is displayed
    await expect(page.locator('[data-testid="daily-view"]')).toBeVisible();
    
    const navigationTimes: number[] = [];
    const maxNavigationTime = 1000; // 1 second in milliseconds
    
    // Repeat for a total of 5 complete navigation cycles
    for (let cycle = 0; cycle < 5; cycle++) {
      // Start timer and click on the 'Weekly View' navigation control
      let startTime = Date.now();
      await page.click('[data-testid="weekly-view-tab"]');
      await expect(page.locator('[data-testid="weekly-view"]')).toBeVisible();
      let endTime = Date.now();
      let navigationTime = endTime - startTime;
      navigationTimes.push(navigationTime);
      
      // Expected Result: Navigation completes within 1 second
      expect(navigationTime).toBeLessThanOrEqual(maxNavigationTime);
      
      // Start timer and click on the 'Monthly View' navigation control
      startTime = Date.now();
      await page.click('[data-testid="monthly-view-tab"]');
      await expect(page.locator('[data-testid="monthly-view"]')).toBeVisible();
      endTime = Date.now();
      navigationTime = endTime - startTime;
      navigationTimes.push(navigationTime);
      
      // Expected Result: Navigation completes within 1 second
      expect(navigationTime).toBeLessThanOrEqual(maxNavigationTime);
      
      // Start timer and click on the 'Daily View' navigation control
      startTime = Date.now();
      await page.click('[data-testid="daily-view-tab"]');
      await expect(page.locator('[data-testid="daily-view"]')).toBeVisible();
      endTime = Date.now();
      navigationTime = endTime - startTime;
      navigationTimes.push(navigationTime);
      
      // Expected Result: Navigation completes within 1 second
      expect(navigationTime).toBeLessThanOrEqual(maxNavigationTime);
    }
    
    // Record and verify all navigation times
    const averageNavigationTime = navigationTimes.reduce((a, b) => a + b, 0) / navigationTimes.length;
    const maxRecordedTime = Math.max(...navigationTimes);
    
    console.log(`Average navigation time: ${averageNavigationTime}ms`);
    console.log(`Maximum navigation time: ${maxRecordedTime}ms`);
    console.log(`All navigation times: ${navigationTimes.join(', ')}ms`);
    
    // Verify all navigation times are within acceptable range
    expect(maxRecordedTime).toBeLessThanOrEqual(maxNavigationTime);
    expect(averageNavigationTime).toBeLessThanOrEqual(maxNavigationTime);
  });

  test('Navigation controls are accessible on all supported devices - Desktop', async ({ page }) => {
    // Set desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    
    // Verify navigation controls are visible and accessible
    await expect(page.locator('[data-testid="daily-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-tab"]')).toBeVisible();
    
    // Test navigation functionality
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view"]')).toBeVisible();
  });

  test('Navigation controls are accessible on all supported devices - Tablet', async ({ page }) => {
    // Set tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });
    
    // Verify navigation controls are visible and accessible
    await expect(page.locator('[data-testid="daily-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-tab"]')).toBeVisible();
    
    // Test navigation functionality
    await page.click('[data-testid="monthly-view-tab"]');
    await expect(page.locator('[data-testid="monthly-view"]')).toBeVisible();
  });

  test('Navigation controls are accessible on all supported devices - Mobile', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Verify navigation controls are visible and accessible
    await expect(page.locator('[data-testid="daily-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="weekly-view-tab"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-view-tab"]')).toBeVisible();
    
    // Test navigation functionality
    await page.click('[data-testid="weekly-view-tab"]');
    await expect(page.locator('[data-testid="weekly-view"]')).toBeVisible();
    
    await page.click('[data-testid="daily-view-tab"]');
    await expect(page.locator('[data-testid="daily-view"]')).toBeVisible();
  });
});