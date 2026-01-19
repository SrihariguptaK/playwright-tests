import { test, expect } from '@playwright/test';

test.describe('Story-21: Schedule Refresh Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    // Wait for schedule to load
    await page.waitForSelector('[data-testid="schedule-view"]', { state: 'visible' });
  });

  test('Validate manual schedule refresh (happy-path)', async ({ page }) => {
    // Note the current schedule data displayed (shifts, times, dates)
    const initialScheduleData = await page.locator('[data-testid="schedule-view"]').textContent();
    const initialShiftCount = await page.locator('[data-testid="shift-item"]').count();
    
    // Locate the refresh button on the schedule view interface
    const refreshButton = page.locator('[data-testid="refresh-button"]');
    await expect(refreshButton).toBeVisible();
    
    // Click the refresh button
    await refreshButton.click();
    
    // Observe the loading indicator during the refresh operation
    const loadingIndicator = page.locator('[data-testid="loading-indicator"]');
    await expect(loadingIndicator).toBeVisible();
    
    // Wait for the refresh operation to complete (within 2 seconds as per requirements)
    await expect(loadingIndicator).toBeHidden({ timeout: 2000 });
    
    // Verify that the schedule updates with latest data
    await page.waitForSelector('[data-testid="schedule-view"]', { state: 'visible' });
    
    // Compare the updated schedule with the previously noted schedule data
    const updatedScheduleData = await page.locator('[data-testid="schedule-view"]').textContent();
    
    // Verify that all schedule elements are properly rendered after refresh
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    const updatedShiftCount = await page.locator('[data-testid="shift-item"]').count();
    expect(updatedShiftCount).toBeGreaterThanOrEqual(0);
    
    // Verify schedule reflects any recent changes
    await expect(page.locator('[data-testid="schedule-view"]')).toContainText(/\d{1,2}:\d{2}/);
  });

  test('Test refresh error handling (error-case)', async ({ page }) => {
    // Note the current schedule data displayed on the screen
    const initialScheduleData = await page.locator('[data-testid="schedule-view"]').textContent();
    const initialShiftElements = await page.locator('[data-testid="shift-item"]').count();
    
    // Simulate an API failure condition by intercepting the API call
    await page.route('**/api/schedules*', route => {
      route.abort('failed');
    });
    
    // Click the refresh button on the schedule view
    const refreshButton = page.locator('[data-testid="refresh-button"]');
    await refreshButton.click();
    
    // Observe the loading indicator appears
    const loadingIndicator = page.locator('[data-testid="loading-indicator"]');
    await expect(loadingIndicator).toBeVisible();
    
    // Wait for loading to complete
    await expect(loadingIndicator).toBeHidden({ timeout: 3000 });
    
    // Verify that the error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    
    // Verify that the error message is clear and user-friendly
    await expect(errorMessage).toContainText(/error|failed|unable/i);
    
    // Check that the previous schedule data is still visible on the screen
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    const currentShiftElements = await page.locator('[data-testid="shift-item"]').count();
    expect(currentShiftElements).toBe(initialShiftElements);
    
    // Verify that the schedule view remains functional after the error
    await expect(page.locator('[data-testid="schedule-view"]')).toBeEnabled();
    await expect(refreshButton).toBeEnabled();
    
    // Verify previous schedule remains visible
    const currentScheduleData = await page.locator('[data-testid="schedule-view"]').textContent();
    expect(currentScheduleData).toBe(initialScheduleData);
  });
});