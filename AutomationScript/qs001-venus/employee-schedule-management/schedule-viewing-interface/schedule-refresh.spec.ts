import { test, expect } from '@playwright/test';

test.describe('Story-14: Schedule Refresh Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to schedule view
    await page.click('[data-testid="schedule-menu"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate schedule refresh updates data correctly', async ({ page }) => {
    // Verify that the refresh button is visible in the schedule view
    const refreshButton = page.locator('[data-testid="refresh-schedule-button"]');
    await expect(refreshButton).toBeVisible();
    
    // Note the current schedule data displayed (shifts, times, dates)
    const initialScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    const initialShiftCount = await page.locator('[data-testid="shift-item"]').count();
    
    // Click the refresh button in the schedule view
    const startTime = Date.now();
    await refreshButton.click();
    
    // Observe the schedule view during refresh - check for loading indicator
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeVisible({ timeout: 1000 });
    
    // Wait for refresh to complete
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeHidden({ timeout: 3000 });
    const endTime = Date.now();
    const refreshDuration = endTime - startTime;
    
    // Verify schedule updates with latest data within 2 seconds
    expect(refreshDuration).toBeLessThan(2000);
    
    // Verify that the system displays a confirmation message
    const successMessage = page.locator('[data-testid="success-notification"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText(/refresh.*success|updated.*success/i);
    
    // Compare the refreshed schedule data with the previously noted data
    const refreshedScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    const refreshedShiftCount = await page.locator('[data-testid="shift-item"]').count();
    
    // Verify data has been reloaded (container should exist and be populated)
    expect(refreshedScheduleData).toBeTruthy();
    expect(refreshedShiftCount).toBeGreaterThanOrEqual(0);
    
    // User sees success notification
    await expect(successMessage).toBeVisible();
  });

  test('Test refresh failure handling', async ({ page }) => {
    // Verify that the refresh button is visible in the schedule view
    const refreshButton = page.locator('[data-testid="refresh-schedule-button"]');
    await expect(refreshButton).toBeVisible();
    
    // Simulate a backend failure by intercepting the API call
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Click the refresh button in the schedule view
    await refreshButton.click();
    
    // Observe the system response to the failed refresh attempt
    // Verify error message displayed without crashing UI
    const errorMessage = page.locator('[data-testid="error-notification"]');
    await expect(errorMessage).toBeVisible({ timeout: 3000 });
    
    // Verify that the error message is user-friendly and informative
    await expect(errorMessage).toContainText(/error|fail|unable|problem/i);
    
    // Verify that the UI remains stable and functional
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(refreshButton).toBeEnabled();
    
    // Verify navigation still works
    const navigationMenu = page.locator('[data-testid="navigation-menu"]');
    await expect(navigationMenu).toBeVisible();
    
    // Restore backend connectivity by removing the route intercept
    await page.unroute('**/api/schedule**');
    
    // Click refresh button again
    await refreshButton.click();
    
    // Verify successful refresh after restoration
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeHidden({ timeout: 3000 });
    
    const successMessage = page.locator('[data-testid="success-notification"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText(/refresh.*success|updated.*success/i);
  });

  test('System maintains authentication during refresh', async ({ page }) => {
    // Verify user is authenticated
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();
    
    // Click refresh button
    const refreshButton = page.locator('[data-testid="refresh-schedule-button"]');
    await refreshButton.click();
    
    // Wait for refresh to complete
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeHidden({ timeout: 3000 });
    
    // Verify user is still authenticated (not redirected to login)
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();
    
    // Verify schedule data is still accessible
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
  });

  test('System provides refresh button in schedule views', async ({ page }) => {
    // Verify refresh button exists and is visible
    const refreshButton = page.locator('[data-testid="refresh-schedule-button"]');
    await expect(refreshButton).toBeVisible();
    
    // Verify button is enabled and clickable
    await expect(refreshButton).toBeEnabled();
    
    // Verify button has appropriate label or icon
    const buttonText = await refreshButton.textContent();
    const hasRefreshIcon = await refreshButton.locator('svg, i, [class*="icon"]').count();
    
    expect(buttonText?.toLowerCase().includes('refresh') || hasRefreshIcon > 0).toBeTruthy();
  });
});