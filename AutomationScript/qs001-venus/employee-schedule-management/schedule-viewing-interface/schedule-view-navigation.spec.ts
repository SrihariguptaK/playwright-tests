import { test, expect } from '@playwright/test';

test.describe('Schedule View Navigation - Story 15', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule dashboard
    await page.waitForURL('**/schedule');
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
  });

  test('Validate navigation between schedule views', async ({ page }) => {
    // Verify default view is displayed
    await expect(page.locator('[data-testid="schedule-view-container"]')).toBeVisible();
    
    // Store employee context before navigation
    const employeeName = await page.locator('[data-testid="employee-name"]').textContent();
    const employeeDepartment = await page.locator('[data-testid="employee-department"]').textContent();
    
    // Action: Employee selects weekly view
    await page.click('[data-testid="weekly-view-button"]');
    
    // Expected Result: Weekly schedule is displayed
    await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="week-days-container"]')).toBeVisible();
    
    // Verify employee context is maintained
    await expect(page.locator('[data-testid="employee-name"]')).toContainText(employeeName);
    await expect(page.locator('[data-testid="employee-department"]')).toContainText(employeeDepartment);
    
    // Action: Employee switches to monthly view
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Monthly schedule is displayed
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText('Monthly');
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify employee context is maintained
    await expect(page.locator('[data-testid="employee-name"]')).toContainText(employeeName);
    await expect(page.locator('[data-testid="employee-department"]')).toContainText(employeeDepartment);
    
    // Action: Employee switches back to daily view
    await page.click('[data-testid="daily-view-button"]');
    
    // Expected Result: Daily schedule is displayed
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-view-title"]')).toContainText('Daily');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify employee context is maintained
    await expect(page.locator('[data-testid="employee-name"]')).toContainText(employeeName);
    await expect(page.locator('[data-testid="employee-department"]')).toContainText(employeeDepartment);
    
    // Verify navigation is error-free
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toHaveCount(0);
  });

  test('Verify load times for schedule views', async ({ page }) => {
    const maxLoadTime = 3000; // 3 seconds in milliseconds
    
    // Navigate to Daily View and measure load time
    const dailyViewStartTime = Date.now();
    await page.click('[data-testid="daily-view-button"]');
    await page.waitForSelector('[data-testid="daily-schedule-view"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const dailyViewLoadTime = Date.now() - dailyViewStartTime;
    
    // Expected Result: Daily view loads within 3 seconds
    expect(dailyViewLoadTime).toBeLessThan(maxLoadTime);
    await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Navigate to Weekly View and measure load time
    const weeklyViewStartTime = Date.now();
    await page.click('[data-testid="weekly-view-button"]');
    await page.waitForSelector('[data-testid="weekly-schedule-view"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const weeklyViewLoadTime = Date.now() - weeklyViewStartTime;
    
    // Expected Result: Weekly view loads within 3 seconds
    expect(weeklyViewLoadTime).toBeLessThan(maxLoadTime);
    await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="week-days-container"]')).toBeVisible();
    
    // Navigate to Monthly View and measure load time
    const monthlyViewStartTime = Date.now();
    await page.click('[data-testid="monthly-view-button"]');
    await page.waitForSelector('[data-testid="monthly-schedule-view"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    const monthlyViewLoadTime = Date.now() - monthlyViewStartTime;
    
    // Expected Result: Monthly view loads within 3 seconds
    expect(monthlyViewLoadTime).toBeLessThan(maxLoadTime);
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Verify no loading errors or timeouts occurred
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toHaveCount(0);
    
    const timeoutWarnings = page.locator('[data-testid="timeout-warning"]');
    await expect(timeoutWarnings).toHaveCount(0);
    
    // Log performance metrics for reporting
    console.log(`Daily View Load Time: ${dailyViewLoadTime}ms`);
    console.log(`Weekly View Load Time: ${weeklyViewLoadTime}ms`);
    console.log(`Monthly View Load Time: ${monthlyViewLoadTime}ms`);
  });
});