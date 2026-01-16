import { test, expect } from '@playwright/test';

test.describe('Schedule Load Confirmation - Story 18', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/');
    // Assume user is already logged in or perform login
    await page.waitForLoadState('networkidle');
  });

  test('Validate loading indicator and success confirmation (happy-path)', async ({ page }) => {
    // Navigate to the schedule section from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Click on the schedule view option to request schedule data
    await page.click('[data-testid="schedule-view-button"]');
    
    // Observe the loading indicator while schedule data is being fetched
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Wait for the schedule data to load completely
    await page.waitForSelector('[data-testid="schedule-data-container"]', { state: 'visible', timeout: 10000 });
    
    // Verify that a success confirmation message or icon appears after data loads
    const successConfirmation = page.locator('[data-testid="schedule-success-message"]');
    await expect(successConfirmation).toBeVisible({ timeout: 5000 });
    
    // Alternative: Check for success icon if message is not present
    const successIcon = page.locator('[data-testid="schedule-success-icon"]');
    const isSuccessMessageVisible = await successConfirmation.isVisible().catch(() => false);
    const isSuccessIconVisible = await successIcon.isVisible().catch(() => false);
    expect(isSuccessMessageVisible || isSuccessIconVisible).toBeTruthy();
    
    // Verify the loading indicator disappears after successful load
    await expect(loadingIndicator).not.toBeVisible({ timeout: 5000 });
    
    // Check that the confirmation is visible on desktop
    await expect(page.locator('[data-testid="schedule-data-container"]')).toBeVisible();
    
    // Verify schedule data is displayed
    const scheduleItems = page.locator('[data-testid="schedule-item"]');
    await expect(scheduleItems.first()).toBeVisible();
  });

  test('Validate loading indicator and success confirmation on tablet device', async ({ page }) => {
    // Set viewport to tablet size
    await page.setViewportSize({ width: 768, height: 1024 });
    
    // Navigate to the schedule section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify loading indicator is displayed
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Wait for schedule data to load
    await page.waitForSelector('[data-testid="schedule-data-container"]', { state: 'visible', timeout: 10000 });
    
    // Verify success confirmation is visible on tablet
    const successConfirmation = page.locator('[data-testid="schedule-success-message"], [data-testid="schedule-success-icon"]');
    await expect(successConfirmation.first()).toBeVisible({ timeout: 5000 });
  });

  test('Validate loading indicator and success confirmation on mobile device', async ({ page }) => {
    // Set viewport to mobile size
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to the schedule section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify loading indicator is displayed
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Wait for schedule data to load
    await page.waitForSelector('[data-testid="schedule-data-container"]', { state: 'visible', timeout: 10000 });
    
    // Verify success confirmation is visible on mobile
    const successConfirmation = page.locator('[data-testid="schedule-success-message"], [data-testid="schedule-success-icon"]');
    await expect(successConfirmation.first()).toBeVisible({ timeout: 5000 });
  });

  test('Validate error message on schedule load failure (error-case)', async ({ page }) => {
    // Configure test environment to simulate schedule data load failure
    // Mock API failure by intercepting the schedule API call
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Navigate to the schedule section and request schedule view
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Wait for the simulated failure to occur
    await page.waitForTimeout(2000);
    
    // Observe the error message displayed to the employee
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    // Verify the error message is user-friendly and does not expose technical details
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.toLowerCase()).toContain('error');
    // Ensure no technical stack traces or API details are exposed
    expect(errorText).not.toMatch(/stack|trace|exception|500|404/i);
    
    // Check that the loading indicator is replaced by the error message
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).not.toBeVisible();
    
    // Verify error message is clearly visible
    await expect(errorMessage).toHaveCSS('display', /block|flex|grid/);
  });

  test('Validate error message visibility on desktop device', async ({ page }) => {
    // Set viewport to desktop size
    await page.setViewportSize({ width: 1920, height: 1080 });
    
    // Mock API failure
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Navigate to schedule view
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify error message is displayed on desktop
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
  });

  test('Validate error message visibility on tablet device', async ({ page }) => {
    // Set viewport to tablet size
    await page.setViewportSize({ width: 768, height: 1024 });
    
    // Mock API failure
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Navigate to schedule view
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify error message is displayed on tablet
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
  });

  test('Validate error message visibility on mobile device', async ({ page }) => {
    // Set viewport to mobile size
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Mock API failure
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Navigate to schedule view
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify error message is displayed on mobile
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
  });

  test('Verify loading indicator disappears after error', async ({ page }) => {
    // Mock API failure
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Navigate to schedule view
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="schedule-view-button"]');
    
    // Verify loading indicator appears initially
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Wait for error to occur
    await page.waitForSelector('[data-testid="schedule-error-message"]', { state: 'visible', timeout: 10000 });
    
    // Verify loading indicator is no longer visible
    await expect(loadingIndicator).not.toBeVisible();
  });
});