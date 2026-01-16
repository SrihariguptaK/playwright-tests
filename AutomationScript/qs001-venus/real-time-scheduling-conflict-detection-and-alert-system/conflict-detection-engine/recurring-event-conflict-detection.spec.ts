import { test, expect } from '@playwright/test';

test.describe('Recurring Event Conflict Detection', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto(BASE_URL);
    // Assume user is already logged in or perform login if needed
  });

  test('Validate detection of conflicts in recurring events (happy-path)', async ({ page }) => {
    // Navigate to the event creation interface
    await page.goto(`${BASE_URL}/events/create`);

    // Enter event details for recurring event
    await page.fill('[data-testid="event-title"]', 'Weekly Team Meeting');
    await page.fill('[data-testid="event-start-time"]', '10:00 AM');
    await page.fill('[data-testid="event-end-time"]', '11:00 AM');
    await page.selectOption('[data-testid="recurrence-pattern"]', 'Weekly');
    await page.check('[data-testid="recurrence-day-monday"]');
    
    // Set start date to current date
    const currentDate = new Date();
    const startDate = currentDate.toISOString().split('T')[0];
    await page.fill('[data-testid="event-start-date"]', startDate);
    
    // Set end date to 3 months from current date
    const endDate = new Date(currentDate.setMonth(currentDate.getMonth() + 3)).toISOString().split('T')[0];
    await page.fill('[data-testid="event-end-date"]', endDate);

    // Click 'Save' or 'Create Event' button
    await page.click('[data-testid="save-event-button"]');

    // Expected Result: Event saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Event saved successfully');

    // Navigate to create a new event that conflicts with the recurring event
    await page.goto(`${BASE_URL}/events/create`);

    // Enter conflicting event details
    await page.fill('[data-testid="event-title"]', 'Training Session');
    await page.fill('[data-testid="event-start-time"]', '10:30 AM');
    await page.fill('[data-testid="event-end-time"]', '11:30 AM');
    
    // Calculate next Monday
    const today = new Date();
    const dayOfWeek = today.getDay();
    const daysUntilMonday = dayOfWeek === 0 ? 1 : (8 - dayOfWeek);
    const nextMonday = new Date(today.setDate(today.getDate() + daysUntilMonday));
    const conflictDate = nextMonday.toISOString().split('T')[0];
    await page.fill('[data-testid="event-date"]', conflictDate);

    // Click 'Save' or 'Create Event' button
    await page.click('[data-testid="save-event-button"]');

    // Expected Result: System detects conflict and alerts user
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');
    
    // Review the conflict alert details
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Weekly Team Meeting');
  });

  test('Verify detection latency for recurring event conflicts (happy-path)', async ({ page }) => {
    // Navigate to the event creation interface
    await page.goto(`${BASE_URL}/events/create`);

    // Enter recurring event details
    await page.fill('[data-testid="event-title"]', 'Daily Standup');
    await page.fill('[data-testid="event-start-time"]', '9:00 AM');
    await page.fill('[data-testid="event-end-time"]', '9:30 AM');
    await page.selectOption('[data-testid="recurrence-pattern"]', 'Daily');
    
    // Set start date to current date
    const currentDate = new Date();
    const startDate = currentDate.toISOString().split('T')[0];
    await page.fill('[data-testid="event-start-date"]', startDate);
    
    // Set end date to 1 month from current date
    const endDate = new Date(currentDate.setMonth(currentDate.getMonth() + 1)).toISOString().split('T')[0];
    await page.fill('[data-testid="event-end-date"]', endDate);

    // Start timer and click 'Save' or 'Create Event' button
    const startTime = Date.now();
    await page.click('[data-testid="save-event-button"]');

    // Wait for system processing and response
    await page.waitForSelector('[data-testid="success-message"], [data-testid="conflict-alert"]', { timeout: 5000 });
    const endTime = Date.now();
    const detectionTime = (endTime - startTime) / 1000;

    // Expected Result: Detection completes within 3 seconds
    expect(detectionTime).toBeLessThanOrEqual(3);
    console.log(`Conflict detection time for non-conflicting recurring event: ${detectionTime} seconds`);

    // Verify success message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Repeat test with a recurring event that has conflicts
    await page.goto(`${BASE_URL}/events/create`);

    // Create event 'Morning Review' that conflicts with Daily Standup
    await page.fill('[data-testid="event-title"]', 'Morning Review');
    await page.fill('[data-testid="event-start-time"]', '9:15 AM');
    await page.fill('[data-testid="event-end-time"]', '9:45 AM');
    
    // Set date to tomorrow
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowDate = tomorrow.toISOString().split('T')[0];
    await page.fill('[data-testid="event-date"]', tomorrowDate);

    // Measure time from submission to conflict alert display
    const conflictStartTime = Date.now();
    await page.click('[data-testid="save-event-button"]');

    // Wait for conflict alert
    await page.waitForSelector('[data-testid="conflict-alert"]', { timeout: 5000 });
    const conflictEndTime = Date.now();
    const conflictDetectionTime = (conflictEndTime - conflictStartTime) / 1000;

    // Expected Result: Detection completes within 3 seconds
    expect(conflictDetectionTime).toBeLessThanOrEqual(3);
    console.log(`Conflict detection time for conflicting event: ${conflictDetectionTime} seconds`);

    // Verify conflict alert is displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Daily Standup');
  });
});