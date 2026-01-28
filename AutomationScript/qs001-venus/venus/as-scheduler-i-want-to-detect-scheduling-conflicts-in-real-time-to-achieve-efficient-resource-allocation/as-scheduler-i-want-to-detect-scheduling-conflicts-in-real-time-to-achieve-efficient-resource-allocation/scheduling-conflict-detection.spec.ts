import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Detection', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling interface and authenticate
    await page.goto(`${baseURL}/schedule`);
    // Assuming authentication is handled via session or login
    await page.waitForSelector('[data-testid="scheduling-interface"]', { timeout: 5000 });
  });

  test('Validate conflict detection with overlapping schedules', async ({ page }) => {
    // Step 1: Navigate to the scheduling interface and access the new booking form
    await page.click('[data-testid="new-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Step 2: Enter scheduling details that overlap with an existing booking
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-01-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.fill('[data-testid="booking-title-input"]', 'Team Meeting');

    // Step 3: Submit the scheduling request
    await page.click('[data-testid="submit-booking-button"]');

    // Step 4: Observe system response for conflict detection alert (within 2 seconds)
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 2000 });
    await expect(conflictAlert).toContainText('conflict', { ignoreCase: true });

    // Step 5: Navigate to the conflict log section
    await page.click('[data-testid="conflict-log-link"]');
    await expect(page.locator('[data-testid="conflict-log-section"]')).toBeVisible();

    // Step 6: Check the conflict log for the newly detected conflict entry
    const conflictLogEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(conflictLogEntry).toBeVisible();
    await expect(conflictLogEntry).toContainText('Conference Room A');
    await expect(conflictLogEntry).toContainText('10:00');

    // Step 7: Review the alert message for resolution options
    await page.click('[data-testid="view-conflict-details"]');
    const alertMessage = page.locator('[data-testid="conflict-alert-message"]');
    await expect(alertMessage).toBeVisible();
    await expect(alertMessage).toContainText('resolution', { ignoreCase: true });
    
    // Verify resolution options are provided
    const resolutionOptions = page.locator('[data-testid="resolution-options"]');
    await expect(resolutionOptions).toBeVisible();
  });

  test('Ensure no false positives in conflict detection', async ({ page }) => {
    // Step 1: Navigate to the scheduling interface and access the new booking form
    await page.click('[data-testid="new-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Step 2: Enter scheduling details that do not overlap with existing bookings
    await page.fill('[data-testid="resource-input"]', 'Conference Room B');
    await page.fill('[data-testid="date-input"]', '2024-01-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="booking-title-input"]', 'Project Review');

    // Step 3: Submit the scheduling request
    await page.click('[data-testid="submit-booking-button"]');

    // Step 4: Observe system response - no conflict alerts should appear
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).not.toBeVisible({ timeout: 2000 });

    // Step 5: Verify success confirmation message is displayed
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible({ timeout: 2000 });
    await expect(successMessage).toContainText('successfully', { ignoreCase: true });

    // Step 6: Navigate to the conflict log section
    await page.click('[data-testid="conflict-log-link"]');
    await expect(page.locator('[data-testid="conflict-log-section"]')).toBeVisible();

    // Step 7: Check the conflict log - no new entries for this request
    const conflictLogEntries = page.locator('[data-testid="conflict-log-entry"]');
    const entriesCount = await conflictLogEntries.count();
    const latestEntry = conflictLogEntries.first();
    
    if (entriesCount > 0) {
      // Verify the latest entry does not contain our booking details
      await expect(latestEntry).not.toContainText('Conference Room B');
      await expect(latestEntry).not.toContainText('Project Review');
    }

    // Step 8: Review the user interface for any alert messages
    await page.goto(`${baseURL}/schedule`);
    const anyAlert = page.locator('[data-testid="alert-message"]');
    await expect(anyAlert).not.toBeVisible();

    // Step 9: Verify the new booking appears in the schedule view
    await page.click('[data-testid="schedule-view-link"]');
    const scheduleView = page.locator('[data-testid="schedule-view"]');
    await expect(scheduleView).toBeVisible();
    
    const newBooking = page.locator('[data-testid="booking-item"]', { hasText: 'Project Review' });
    await expect(newBooking).toBeVisible();
    await expect(newBooking).toContainText('Conference Room B');
    await expect(newBooking).toContainText('14:00');
  });
});