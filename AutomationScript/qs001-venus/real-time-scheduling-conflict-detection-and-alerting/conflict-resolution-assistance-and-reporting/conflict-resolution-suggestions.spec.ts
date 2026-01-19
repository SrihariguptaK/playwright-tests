import { test, expect } from '@playwright/test';

test.describe('Story-16: Conflict Resolution Suggestions', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_EMAIL = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'password123';
  const SUGGESTION_TIMEOUT = 2000;

  test.beforeEach(async ({ page }) => {
    // Log into the scheduling system using scheduler credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify generation of resolution suggestions for conflicts (happy-path)', async ({ page }) => {
    // Navigate to the booking creation interface
    await page.click('[data-testid="create-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Create an initial booking by selecting a resource, date, and time slot, then save the booking
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room A' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Start a timer and attempt to create a second booking with the same resource and overlapping time slot
    await page.click('[data-testid="create-booking-button"]');
    const startTime = Date.now();
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room A' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.click('[data-testid="save-booking-button"]');

    // Wait for conflict alert and suggestions to appear
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: SUGGESTION_TIMEOUT });
    const endTime = Date.now();
    const elapsedTime = endTime - startTime;

    // Stop the timer and verify the time elapsed for suggestion generation
    expect(elapsedTime).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);

    // Verify that the conflict alert interface displays the generated suggestions
    await expect(page.locator('[data-testid="resolution-suggestions"]')).toBeVisible();

    // Review the suggestions to verify they include alternative time slots
    const timeSlotSuggestions = page.locator('[data-testid="suggestion-time-slot"]');
    await expect(timeSlotSuggestions).toHaveCount(await timeSlotSuggestions.count());
    expect(await timeSlotSuggestions.count()).toBeGreaterThan(0);

    // Review the suggestions to verify they include alternative resources
    const resourceSuggestions = page.locator('[data-testid="suggestion-resource"]');
    const suggestionCount = await resourceSuggestions.count();
    
    // Verify each suggested alternative time slot by checking against existing bookings
    const allSuggestions = page.locator('[data-testid="suggestion-item"]');
    const totalSuggestions = await allSuggestions.count();
    expect(totalSuggestions).toBeGreaterThan(0);

    // Verify each suggestion has conflict-free indicator
    for (let i = 0; i < totalSuggestions; i++) {
      const suggestion = allSuggestions.nth(i);
      await expect(suggestion.locator('[data-testid="conflict-free-badge"]')).toBeVisible();
    }
  });

  test('Test application of a suggested resolution (happy-path)', async ({ page }) => {
    // Setup: Create initial booking to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room B' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Conference Room B' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.click('[data-testid="save-booking-button"]');

    // Review the displayed resolution suggestions in the conflict alert interface
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="resolution-suggestions"]')).toBeVisible();

    // Select the first suggested resolution option by clicking on it
    const firstSuggestion = page.locator('[data-testid="suggestion-item"]').first();
    await firstSuggestion.click();
    await expect(firstSuggestion).toHaveClass(/selected/);

    // Click the 'Apply' button to apply the selected suggestion
    await page.click('[data-testid="apply-suggestion-button"]');

    // Verify that the booking is updated according to the selected suggestion
    await expect(page.locator('[data-testid="booking-updated-message"]')).toBeVisible();

    // Navigate to the booking list or calendar view to verify the updated booking
    await page.click('[data-testid="view-bookings-button"]');
    await expect(page.locator('[data-testid="bookings-list"]')).toBeVisible();

    // Verify that the original conflicting booking remains unchanged
    const originalBooking = page.locator('[data-testid="booking-item"]').filter({ hasText: '14:00' });
    await expect(originalBooking).toBeVisible();

    // Trigger the system's conflict validation process by refreshing the schedule
    await page.reload();
    await expect(page.locator('[data-testid="bookings-list"]')).toBeVisible();

    // Review the validation results to confirm no conflicts are detected
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();

    // Verify that no conflict alerts or warnings are displayed for the updated booking
    await expect(page.locator('[data-testid="conflict-warning"]')).not.toBeVisible();

    // Check the booking status to ensure it is marked as confirmed and active
    const updatedBooking = page.locator('[data-testid="booking-item"]').last();
    await expect(updatedBooking.locator('[data-testid="booking-status"]')).toHaveText(/confirmed|active/i);
  });

  test('Ensure suggestion generation performance under 2 seconds (boundary)', async ({ page }) => {
    const performanceResults: number[] = [];

    // Test iteration 1
    await page.click('[data-testid="create-booking-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 1' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Prepare performance monitoring and start timer
    await page.click('[data-testid="create-booking-button"]');
    const startTime1 = Date.now();
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 1' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:30');
    await page.fill('[data-testid="end-time-input"]', '10:30');
    await page.click('[data-testid="save-booking-button"]');

    // Monitor system response and stop timer when suggestions are displayed
    await expect(page.locator('[data-testid="resolution-suggestions"]')).toBeVisible();
    const endTime1 = Date.now();
    const elapsed1 = endTime1 - startTime1;
    performanceResults.push(elapsed1);

    // Verify that the elapsed time is less than or equal to 2 seconds
    expect(elapsed1).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);

    // Verify that suggestions returned are valid and complete
    const suggestions1 = page.locator('[data-testid="suggestion-item"]');
    expect(await suggestions1.count()).toBeGreaterThan(0);
    await page.click('[data-testid="cancel-button"]');

    // Test iteration 2 - Repeat with different parameters
    await page.click('[data-testid="create-booking-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 2' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-18');
    await page.fill('[data-testid="start-time-input"]', '13:00');
    await page.fill('[data-testid="end-time-input"]', '14:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    await page.click('[data-testid="create-booking-button"]');
    const startTime2 = Date.now();
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 2' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-18');
    await page.fill('[data-testid="start-time-input"]', '13:45');
    await page.fill('[data-testid="end-time-input"]', '14:45');
    await page.click('[data-testid="save-booking-button"]');

    await expect(page.locator('[data-testid="resolution-suggestions"]')).toBeVisible();
    const endTime2 = Date.now();
    const elapsed2 = endTime2 - startTime2;
    performanceResults.push(elapsed2);

    // Measure the suggestion generation time for the second conflict
    expect(elapsed2).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);
    await page.click('[data-testid="cancel-button"]');

    // Test iteration 3
    await page.click('[data-testid="create-booking-button"]');
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 3' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-19');
    await page.fill('[data-testid="start-time-input"]', '16:00');
    await page.fill('[data-testid="end-time-input"]', '17:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    await page.click('[data-testid="create-booking-button"]');
    const startTime3 = Date.now();
    await page.selectOption('[data-testid="resource-select"]', { label: 'Meeting Room 3' });
    await page.fill('[data-testid="booking-date-input"]', '2024-03-19');
    await page.fill('[data-testid="start-time-input"]', '16:20');
    await page.fill('[data-testid="end-time-input"]', '17:20');
    await page.click('[data-testid="save-booking-button"]');

    await expect(page.locator('[data-testid="resolution-suggestions"]')).toBeVisible();
    const endTime3 = Date.now();
    const elapsed3 = endTime3 - startTime3;
    performanceResults.push(elapsed3);

    // Trigger a third conflict scenario and measure performance
    expect(elapsed3).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);

    // Calculate the average suggestion generation time across all three tests
    const averageTime = performanceResults.reduce((sum, time) => sum + time, 0) / performanceResults.length;
    expect(averageTime).toBeLessThanOrEqual(SUGGESTION_TIMEOUT);

    console.log(`Performance Results: ${performanceResults.join(', ')}ms`);
    console.log(`Average Time: ${averageTime}ms`);
  });
});