import { test, expect } from '@playwright/test';

test.describe('Detect overlapping bookings to avoid double scheduling', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to booking creation page and ensure scheduler is logged in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'scheduler123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Detect overlapping booking and prevent confirmation (happy-path)', async ({ page }) => {
    // Navigate to the booking creation page
    await page.goto(`${BASE_URL}/bookings/create`);
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Select resource 'Conference Room A' from the resource dropdown
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await expect(page.locator('[data-testid="resource-dropdown"]')).toContainText('Conference Room A');

    // Enter current date in the date field
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="booking-date-input"]', currentDate);

    // Enter start time as 10:15 AM and end time as 10:45 AM (overlapping with existing 10:00 AM - 11:00 AM booking)
    await page.fill('[data-testid="start-time-input"]', '10:15');
    await page.fill('[data-testid="end-time-input"]', '10:45');

    // Click 'Submit' or 'Confirm Booking' button
    await page.click('[data-testid="submit-booking-button"]');

    // Expected Result: System displays conflict warning and blocks booking confirmation
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('conflict');
    await expect(page.locator('[data-testid="confirm-booking-button"]')).toBeDisabled();

    // Verify that the booking cannot be saved by attempting to click confirm again
    const isDisabled = await page.locator('[data-testid="confirm-booking-button"]').isDisabled();
    expect(isDisabled).toBeTruthy();

    // Modify the start time to 11:00 AM and end time to 12:00 PM (non-overlapping slot)
    await page.fill('[data-testid="start-time-input"]', '11:00');
    await page.fill('[data-testid="end-time-input"]', '12:00');

    // Click 'Submit' or 'Confirm Booking' button
    await page.click('[data-testid="submit-booking-button"]');

    // Expected Result: System allows booking confirmation without warnings
    await expect(page.locator('[data-testid="conflict-warning"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="confirm-booking-button"]')).toBeEnabled();
    await page.click('[data-testid="confirm-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Navigate to conflict logs section or access logs via API endpoint GET /api/conflicts/logs
    await page.goto(`${BASE_URL}/admin/conflict-logs`);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();

    // Search for conflict log entry related to 'Conference Room A' for the attempted booking at 10:15 AM - 10:45 AM
    await page.fill('[data-testid="log-search-input"]', 'Conference Room A');
    await page.click('[data-testid="log-search-button"]');

    // Expected Result: Conflict logged with correct resource and timestamp
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Conference Room A');
    await expect(logEntry).toContainText('10:15');
    await expect(logEntry).toContainText('10:45');
  });

  test('Verify conflict detection latency under 1 second (boundary)', async ({ page }) => {
    // Navigate to booking creation page
    await page.goto(`${BASE_URL}/bookings/create`);
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Fill in resource 'Meeting Room B', current date, start time 2:15 PM, end time 2:45 PM
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-meeting-room-b"]');
    
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="booking-date-input"]', currentDate);
    await page.fill('[data-testid="start-time-input"]', '14:15');
    await page.fill('[data-testid="end-time-input"]', '14:45');

    // Note the current timestamp and click 'Submit' or 'Check Availability' button
    const startTime = Date.now();
    await page.click('[data-testid="submit-booking-button"]');

    // Measure the time elapsed from submission to conflict warning display
    await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 2000 });
    const endTime = Date.now();
    const latency = endTime - startTime;

    // Expected Result: System processes conflict detection within 1 second
    expect(latency).toBeLessThan(1000);

    // Expected Result: Conflict warning displayed immediately
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();

    // Verify the booking confirmation button state
    await expect(page.locator('[data-testid="confirm-booking-button"]')).toBeDisabled();

    // Expected Result: Booking cannot be saved with conflict
    const confirmButton = page.locator('[data-testid="confirm-booking-button"]');
    const isDisabled = await confirmButton.isDisabled();
    expect(isDisabled).toBeTruthy();
  });

  test('Ensure system logs all detected conflicts (happy-path)', async ({ page }) => {
    // Navigate to booking creation page as Scheduler user
    await page.goto(`${BASE_URL}/bookings/create`);
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Create a conflicting booking attempt by selecting resource 'Projector Unit 5'
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-projector-unit-5"]');
    
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="booking-date-input"]', currentDate);
    await page.fill('[data-testid="start-time-input"]', '09:30');
    await page.fill('[data-testid="end-time-input"]', '10:30');

    // Click 'Submit' button to trigger conflict detection
    const conflictDetectionTime = new Date();
    await page.click('[data-testid="submit-booking-button"]');

    // Expected Result: Conflict detected and logged
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();

    // Log in as Admin user or switch to admin interface
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'admin123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to conflict logs section
    await page.goto(`${BASE_URL}/admin/conflict-logs`);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();

    // Query or filter logs for resource 'Projector Unit 5'
    await page.fill('[data-testid="log-search-input"]', 'Projector Unit 5');
    await page.click('[data-testid="log-search-button"]');

    // Expected Result: Log entry present with correct details
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toBeVisible();

    // Open the specific log entry and review its contents
    await logEntry.click();
    await expect(page.locator('[data-testid="log-detail-modal"]')).toBeVisible();

    // Expected Result: Timestamp and resource information accurate
    const logTimestamp = await page.locator('[data-testid="log-timestamp"]').textContent();
    const logResource = await page.locator('[data-testid="log-resource"]').textContent();
    const logStartTime = await page.locator('[data-testid="log-start-time"]').textContent();
    const logEndTime = await page.locator('[data-testid="log-end-time"]').textContent();

    // Verify resource information accuracy
    expect(logResource).toContain('Projector Unit 5');
    expect(logStartTime).toContain('09:30');
    expect(logEndTime).toContain('10:30');

    // Verify the timestamp matches within acceptable margin
    const logDate = new Date(logTimestamp || '');
    const timeDifference = Math.abs(logDate.getTime() - conflictDetectionTime.getTime());
    expect(timeDifference).toBeLessThan(60000); // Within 60 seconds

    // Check log metadata for completeness
    await expect(page.locator('[data-testid="log-user-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-session-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-resolution-status"]')).toBeVisible();
  });
});