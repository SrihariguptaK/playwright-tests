import { test, expect } from '@playwright/test';

test.describe('Story-18: Schedule Load Confirmation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as employee
    await page.goto('/');
    await page.fill('[data-testid="username-input"]', 'employee@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate loading indicator and success confirmation (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the schedule section from the main menu
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Step 2: Observe the screen immediately after requesting the schedule view
    // Expected Result: Loading indicator is displayed
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Step 3: Wait for the schedule data to complete loading
    await page.waitForLoadState('networkidle');
    
    // Step 4: Observe the screen once schedule data has finished loading
    // Expected Result: Success confirmation message or icon is displayed
    const successMessage = page.locator('[data-testid="schedule-success-message"]');
    await expect(successMessage).toBeVisible({ timeout: 5000 });
    
    // Alternative: Check for success icon
    const successIcon = page.locator('[data-testid="schedule-success-icon"]');
    const isSuccessIconVisible = await successIcon.isVisible().catch(() => false);
    
    if (isSuccessIconVisible) {
      await expect(successIcon).toBeVisible();
    }
    
    // Step 5: Verify that the schedule data is displayed correctly on the screen
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).toBeVisible();
    
    // Verify schedule has data loaded
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    await expect(scheduleEntries.first()).toBeVisible();
    
    // Step 6: Navigate to a different view and return to the schedule view
    await page.click('[data-testid="dashboard-menu-item"]');
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    
    // Return to schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    await expect(successMessage).toBeVisible({ timeout: 5000 });
    await expect(scheduleContainer).toBeVisible();
    
    // Step 7: Test on a mobile device or responsive view
    await page.setViewportSize({ width: 375, height: 667 });
    await page.reload();
    
    // Verify loading indicator is visible on mobile
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Verify success confirmation is visible on mobile
    await expect(successMessage).toBeVisible({ timeout: 5000 });
    
    // Verify schedule data is displayed on mobile
    await expect(scheduleContainer).toBeVisible();
    
    // Verify loading and confirmation indicators are accessible
    await expect(loadingIndicator).toHaveAttribute('role', /.+/);
    await expect(successMessage).toHaveAttribute('aria-live', 'polite');
  });

  test('Validate error message on schedule load failure (error-case)', async ({ page, context }) => {
    // Step 1: Simulate a schedule data load failure by blocking the API endpoint
    await context.route('**/api/schedules/monthly', route => {
      route.abort('failed');
    });
    
    // Step 2: Navigate to the schedule section to request schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Observe loading indicator appears
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
    
    // Step 3: Wait for the system to detect the load failure
    await page.waitForTimeout(3000);
    
    // Step 4: Observe the error message displayed on the screen
    // Expected Result: Error message is displayed clearly to the employee
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    // Step 5: Verify the error message is visible and readable on the current device
    await expect(errorMessage).toHaveText(/error|failed|unable to load/i);
    
    // Verify error message has proper styling for visibility
    const errorMessageColor = await errorMessage.evaluate(el => {
      return window.getComputedStyle(el).color;
    });
    expect(errorMessageColor).toBeTruthy();
    
    // Step 6: Check if the error message provides actionable guidance
    const retryButton = page.locator('[data-testid="schedule-retry-button"]');
    const contactSupportLink = page.locator('[data-testid="contact-support-link"]');
    
    const hasRetryButton = await retryButton.isVisible().catch(() => false);
    const hasContactSupport = await contactSupportLink.isVisible().catch(() => false);
    
    expect(hasRetryButton || hasContactSupport).toBeTruthy();
    
    // Verify error message is accessible
    await expect(errorMessage).toHaveAttribute('role', 'alert');
    
    // Test on mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(errorMessage).toBeVisible();
    
    // Step 7: Restore network connection and attempt to reload the schedule
    await context.unroute('**/api/schedules/monthly');
    
    // Click retry button if available
    if (hasRetryButton) {
      await retryButton.click();
      
      // Verify loading indicator appears again
      await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
      
      // Verify success confirmation after retry
      const successMessage = page.locator('[data-testid="schedule-success-message"]');
      await expect(successMessage).toBeVisible({ timeout: 5000 });
      
      // Verify schedule data is now displayed
      const scheduleContainer = page.locator('[data-testid="schedule-container"]');
      await expect(scheduleContainer).toBeVisible();
    } else {
      // Manual reload if no retry button
      await page.reload();
      await page.click('[data-testid="schedule-menu-item"]');
      
      const successMessage = page.locator('[data-testid="schedule-success-message"]');
      await expect(successMessage).toBeVisible({ timeout: 5000 });
    }
  });

  test('Validate loading indicator appears during schedule data fetch', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Verify loading indicator is displayed immediately
    const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
    await expect(loadingIndicator).toBeVisible({ timeout: 1000 });
    
    // Verify loading indicator has appropriate attributes
    await expect(loadingIndicator).toHaveAttribute('aria-busy', 'true');
    
    // Wait for loading to complete
    await page.waitForLoadState('networkidle');
    
    // Verify loading indicator is hidden after load
    await expect(loadingIndicator).toBeHidden({ timeout: 5000 });
  });

  test('Validate success confirmation message appears after successful load', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Wait for schedule to load
    await page.waitForLoadState('networkidle');
    
    // Verify success confirmation message or icon is displayed
    const successMessage = page.locator('[data-testid="schedule-success-message"]');
    const successIcon = page.locator('[data-testid="schedule-success-icon"]');
    
    const hasSuccessMessage = await successMessage.isVisible().catch(() => false);
    const hasSuccessIcon = await successIcon.isVisible().catch(() => false);
    
    expect(hasSuccessMessage || hasSuccessIcon).toBeTruthy();
    
    if (hasSuccessMessage) {
      await expect(successMessage).toContainText(/success|loaded|complete/i);
    }
  });

  test('Validate error message clarity on schedule load failure', async ({ page, context }) => {
    // Block API endpoint to simulate failure
    await context.route('**/api/schedules/monthly', route => {
      route.abort('failed');
    });
    
    // Navigate to schedule view
    await page.click('[data-testid="schedule-menu-item"]');
    
    // Wait for error to appear
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    // Verify error message is clear and informative
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText!.length).toBeGreaterThan(10);
    
    // Verify error message contains helpful information
    expect(errorText).toMatch(/error|failed|unable|problem|issue/i);
  });

  test('Validate loading and confirmation indicators are accessible on all devices', async ({ page }) => {
    const viewports = [
      { width: 1920, height: 1080, name: 'Desktop' },
      { width: 768, height: 1024, name: 'Tablet' },
      { width: 375, height: 667, name: 'Mobile' }
    ];
    
    for (const viewport of viewports) {
      // Set viewport size
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      
      // Navigate to schedule view
      await page.click('[data-testid="schedule-menu-item"]');
      
      // Verify loading indicator is visible
      const loadingIndicator = page.locator('[data-testid="schedule-loading-indicator"]');
      await expect(loadingIndicator).toBeVisible({ timeout: 2000 });
      
      // Wait for load to complete
      await page.waitForLoadState('networkidle');
      
      // Verify success confirmation is visible
      const successMessage = page.locator('[data-testid="schedule-success-message"]');
      await expect(successMessage).toBeVisible({ timeout: 5000 });
      
      // Verify schedule container is visible
      const scheduleContainer = page.locator('[data-testid="schedule-container"]');
      await expect(scheduleContainer).toBeVisible();
      
      // Navigate away for next iteration
      await page.click('[data-testid="dashboard-menu-item"]');
    }
  });
});