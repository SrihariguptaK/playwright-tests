import { test, expect } from '@playwright/test';

test.describe('Visual Conflict Indicators on Calendar', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling calendar and login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.goto('/schedule/calendar');
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
  });

  test('Verify visual conflict indicators on calendar (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the scheduling calendar view
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();

    // Step 2: Create a booking for Resource A from 10:00 AM to 12:00 PM on a specific date
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource A');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '12:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource A' }).first()).toBeVisible();

    // Step 3: Create a second booking for Resource A from 11:00 AM to 1:00 PM on the same date (overlapping time)
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource A');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '11:00');
    await page.fill('[data-testid="end-time"]', '13:00');
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: Conflict indicators appear on calendar entries
    await expect(page.locator('[data-testid="conflict-indicator"]').first()).toBeVisible({ timeout: 2000 });
    const conflictIndicators = page.locator('[data-testid="conflict-indicator"]');
    await expect(conflictIndicators).toHaveCount(2);

    // Step 4: Click on the conflict indicator on the first booking
    await page.locator('[data-testid="conflict-indicator"]').first().click();

    // Expected Result: Detailed conflict information is displayed
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('Resource A');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('11:00');

    // Step 5: Close the conflict details popup or panel
    await page.click('[data-testid="close-conflict-details"]');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).not.toBeVisible();

    // Step 6: Modify the second booking to change the time from 1:00 PM to 3:00 PM (no overlap)
    const secondBooking = page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource A' }).filter({ hasText: '11:00' });
    await secondBooking.click();
    await page.click('[data-testid="edit-booking-button"]');
    await page.fill('[data-testid="start-time"]', '13:00');
    await page.fill('[data-testid="end-time"]', '15:00');
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: Conflict indicator is removed from calendar
    await expect(page.locator('[data-testid="conflict-indicator"]')).toHaveCount(0, { timeout: 2000 });

    // Step 7: Observe the calendar entries for both bookings
    const bookings = page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource A' });
    await expect(bookings).toHaveCount(2);
  });

  test('Test real-time update of conflict indicators (happy-path)', async ({ page }) => {
    // Step 1: Note the current time and observe an existing booking on the calendar
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource B');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '14:00');
    await page.fill('[data-testid="end-time"]', '16:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource B' })).toBeVisible();

    // Step 2: Create a new booking for Resource B from 3:00 PM to 5:00 PM (creating an overlap)
    const startTime = Date.now();
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource B');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '15:00');
    await page.fill('[data-testid="end-time"]', '17:00');
    await page.click('[data-testid="save-booking-button"]');

    // Step 3: Measure the time from booking creation to conflict indicator appearance
    await expect(page.locator('[data-testid="conflict-indicator"]').first()).toBeVisible({ timeout: 2000 });
    const indicatorAppearTime = Date.now() - startTime;

    // Expected Result: Conflict indicator appears within 1 second
    expect(indicatorAppearTime).toBeLessThan(1000);

    // Step 4: Verify that both bookings now display conflict indicators
    const conflictIndicators = page.locator('[data-testid="conflict-indicator"]');
    await expect(conflictIndicators).toHaveCount(2);

    // Step 5: Note the current time and modify the new booking to change the time from 4:00 PM to 6:00 PM (removing overlap)
    const modifyStartTime = Date.now();
    const secondBooking = page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource B' }).filter({ hasText: '15:00' });
    await secondBooking.click();
    await page.click('[data-testid="edit-booking-button"]');
    await page.fill('[data-testid="start-time"]', '16:00');
    await page.fill('[data-testid="end-time"]', '18:00');
    await page.click('[data-testid="save-booking-button"]');

    // Step 6: Measure the time from booking modification to conflict indicator removal
    await expect(page.locator('[data-testid="conflict-indicator"]')).toHaveCount(0, { timeout: 2000 });
    const indicatorRemovalTime = Date.now() - modifyStartTime;

    // Expected Result: Conflict indicator disappears within 1 second
    expect(indicatorRemovalTime).toBeLessThan(1000);

    // Step 7: Verify that no conflict indicators remain on either booking
    await expect(page.locator('[data-testid="conflict-indicator"]')).toHaveCount(0);
  });

  test('Check conflict indicators on mobile interface (happy-path)', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Step 1: Open the scheduling application on a mobile device and log in as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Step 2: Navigate to the calendar view on the mobile interface
    await page.goto('/schedule/calendar');
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();

    // Step 3: Create a booking for Resource C from 9:00 AM to 11:00 AM on a specific date
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource C');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '09:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-entry"]').filter({ hasText: 'Resource C' })).toBeVisible();

    // Step 4: Create a conflicting booking for Resource C from 10:00 AM to 12:00 PM on the same date
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Resource C');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '12:00');
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: Conflict indicators are visible and functional
    await expect(page.locator('[data-testid="conflict-indicator"]').first()).toBeVisible({ timeout: 2000 });
    const conflictIndicators = page.locator('[data-testid="conflict-indicator"]');
    await expect(conflictIndicators).toHaveCount(2);

    // Step 5: Tap on the conflict indicator on the first booking
    await page.locator('[data-testid="conflict-indicator"]').first().tap();

    // Expected Result: Conflict details are accessible on mobile
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();

    // Step 6: Review the conflict details including overlapping times, affected resource, and booking information
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('Resource C');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toContainText('overlap');

    // Step 7: Close the conflict details and tap on the conflict indicator on the second booking
    await page.click('[data-testid="close-conflict-details"]');
    await expect(page.locator('[data-testid="conflict-details-panel"]')).not.toBeVisible();
    await page.locator('[data-testid="conflict-indicator"]').nth(1).tap();
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();

    // Step 8: Verify touch responsiveness and visual clarity of conflict indicators
    const indicator = page.locator('[data-testid="conflict-indicator"]').first();
    const boundingBox = await indicator.boundingBox();
    expect(boundingBox).not.toBeNull();
    if (boundingBox) {
      expect(boundingBox.width).toBeGreaterThan(24); // Minimum touch target size
      expect(boundingBox.height).toBeGreaterThan(24);
    }

    // Verify visual properties
    await expect(indicator).toBeVisible();
    const color = await indicator.evaluate((el) => window.getComputedStyle(el).color);
    expect(color).toBeTruthy();
  });
});