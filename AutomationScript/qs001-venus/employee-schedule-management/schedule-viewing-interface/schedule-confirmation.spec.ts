import { test, expect } from '@playwright/test';

test.describe('Schedule Load Confirmation - Story 14', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login
    await page.goto('/');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate confirmation message on successful load (happy-path)', async ({ page }) => {
    // Employee navigates to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Employee requests schedule view by selecting a schedule view option (daily, weekly, or monthly)
    await page.click('[data-testid="schedule-view-selector"]');
    await page.click('[data-testid="weekly-view-option"]');

    // System retrieves schedule data from the Schedule API
    // Wait for schedule to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );

    // Employee observes the confirmation message after schedule loads
    const confirmationMessage = page.locator('[data-testid="schedule-confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });

    // Employee verifies that the confirmation message is clearly visible and appropriately styled
    await expect(confirmationMessage).toHaveText(/schedule.*loaded.*successfully/i);
    await expect(confirmationMessage).toHaveCSS('display', 'block');

    // Employee waits to observe if the confirmation message auto-dismisses or requires manual dismissal
    await page.waitForTimeout(2000);

    // Employee verifies that the displayed schedule data matches expected shifts
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    await expect(scheduleGrid).toBeVisible();
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    await expect(scheduleEntries).toHaveCount(await scheduleEntries.count());
    expect(await scheduleEntries.count()).toBeGreaterThan(0);
  });

  test('Validate error message and retry on failure (error-case)', async ({ page }) => {
    // Test engineer configures the test environment to simulate API failure for schedule load request
    await page.route('**/api/schedule*', route => {
      route.abort('failed');
    });

    // Employee navigates to the schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Employee requests schedule view by selecting a schedule view option
    await page.click('[data-testid="schedule-view-selector"]');
    await page.click('[data-testid="weekly-view-option"]');

    // System attempts to retrieve schedule data from the Schedule API which fails due to simulated error
    // Employee observes the error handling behavior
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });

    // Employee verifies that the error message includes a retry option
    const retryButton = page.locator('[data-testid="schedule-retry-button"]');
    await expect(retryButton).toBeVisible();

    // Employee verifies that the error message is clearly visible and appropriately styled
    await expect(errorMessage).toHaveText(/failed.*load.*schedule/i);
    await expect(errorMessage).toHaveCSS('display', 'block');
    await expect(retryButton).toHaveText(/retry/i);

    // Test engineer restores normal API functionality to allow successful schedule load
    await page.unroute('**/api/schedule*');

    // Employee clicks the retry button or link
    await retryButton.click();

    // System retrieves schedule data from the Schedule API successfully
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );

    // Employee observes the confirmation message after successful retry
    const confirmationMessage = page.locator('[data-testid="schedule-confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });
    await expect(confirmationMessage).toHaveText(/schedule.*loaded.*successfully/i);

    // Verify schedule data is displayed
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    await expect(scheduleGrid).toBeVisible();
  });

  test('Validate confirmation message on successful load - Test Case #1', async ({ page }) => {
    // Employee requests schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="schedule-view-selector"]');
    await page.click('[data-testid="daily-view-option"]');

    // Expected Result: Schedule loads and confirmation message is displayed
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );
    
    const confirmationMessage = page.locator('[data-testid="schedule-confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });
    
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    await expect(scheduleGrid).toBeVisible();
  });

  test('Validate error message and retry on failure - Test Case #2', async ({ page }) => {
    // Action: Simulate API failure during schedule load
    await page.route('**/api/schedule*', route => {
      route.abort('failed');
    });

    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="schedule-view-selector"]');
    await page.click('[data-testid="monthly-view-option"]');

    // Expected Result: Error message displayed with retry option
    const errorMessage = page.locator('[data-testid="schedule-error-message"]');
    await expect(errorMessage).toBeVisible();
    
    const retryButton = page.locator('[data-testid="schedule-retry-button"]');
    await expect(retryButton).toBeVisible();

    // Action: Employee clicks retry
    await page.unroute('**/api/schedule*');
    await retryButton.click();

    // Expected Result: Schedule reload attempted
    await page.waitForResponse(response => 
      response.url().includes('/api/schedule') && response.status() === 200
    );
    
    const confirmationMessage = page.locator('[data-testid="schedule-confirmation-message"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 1000 });
  });
});