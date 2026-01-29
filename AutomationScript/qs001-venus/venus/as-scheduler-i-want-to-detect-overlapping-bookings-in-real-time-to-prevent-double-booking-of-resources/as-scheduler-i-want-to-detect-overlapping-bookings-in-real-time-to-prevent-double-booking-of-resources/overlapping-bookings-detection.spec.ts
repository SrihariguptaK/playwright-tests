import { test, expect } from '@playwright/test';

test.describe('Overlapping Bookings Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduler dashboard
    await page.goto('/scheduler/dashboard');
    // Login as scheduler if needed
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-title"]')).toBeVisible();
  });

  test('should detect overlapping booking for same resource within 1 second', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Booking created successfully');

    // Attempt to create overlapping booking
    const startTime = Date.now();
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T11:30');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify conflict detected within 1 second
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    const detectionTime = Date.now() - startTime;
    expect(detectionTime).toBeLessThan(1000);
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Overlapping booking detected');
  });

  test('should detect overlapping single booking with exact same time slot', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Attempt to create booking with exact same time
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-02-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-16T15:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify conflict detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Meeting Room B');
  });

  test('should detect overlapping recurring booking', async ({ page }) => {
    // Create recurring booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-02-20T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-20T10:00');
    await page.check('[data-testid="recurring-checkbox"]');
    await page.selectOption('[data-testid="recurrence-pattern"]', 'weekly');
    await page.fill('[data-testid="recurrence-end-date"]', '2024-03-20');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Attempt to create overlapping booking on recurring date
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Training Room C');
    await page.fill('[data-testid="start-time-input"]', '2024-02-27T09:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-27T10:30');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify conflict detected for recurring instance
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Conflicts with recurring booking');
  });

  test('should log conflict with timestamp, resource ID, and booking details', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Lab Room D');
    await page.fill('[data-testid="start-time-input"]', '2024-02-18T13:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-18T14:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create overlapping booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Lab Room D');
    await page.fill('[data-testid="start-time-input"]', '2024-02-18T13:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-18T14:30');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();

    // Navigate to conflict logs
    await page.click('[data-testid="view-conflicts-button"]');
    await expect(page.locator('[data-testid="conflicts-log"]')).toBeVisible();
    
    // Verify log entry contains required details
    const logEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(logEntry).toContainText('Lab Room D');
    await expect(logEntry.locator('[data-testid="conflict-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="conflict-resource-id"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="conflict-booking-details"]')).toContainText('2024-02-18');
  });

  test('should prevent booking confirmation when conflict detected', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Auditorium E');
    await page.fill('[data-testid="start-time-input"]', '2024-02-22T16:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-22T18:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Attempt overlapping booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Auditorium E');
    await page.fill('[data-testid="start-time-input"]', '2024-02-22T17:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-22T19:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify booking is not confirmed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-booking-button"]')).toBeDisabled();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot confirm booking due to conflict');
  });

  test('should allow authorized user to override conflict and confirm booking', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Studio F');
    await page.fill('[data-testid="start-time-input"]', '2024-02-25T11:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-25T12:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Attempt overlapping booking as authorized user
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Studio F');
    await page.fill('[data-testid="start-time-input"]', '2024-02-25T11:30');
    await page.fill('[data-testid="end-time-input"]', '2024-02-25T12:30');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Override conflict
    await page.click('[data-testid="override-conflict-button"]');
    await page.fill('[data-testid="override-reason-input"]', 'Emergency booking approved by manager');
    await page.click('[data-testid="confirm-override-button"]');
    
    // Verify booking confirmed
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Booking confirmed with override');
  });

  test('should handle concurrent booking requests without missing conflicts', async ({ page, context }) => {
    // Open multiple tabs to simulate concurrent requests
    const page2 = await context.newPage();
    await page2.goto('/scheduler/dashboard');
    await page2.fill('[data-testid="username-input"]', 'scheduler2@test.com');
    await page2.fill('[data-testid="password-input"]', 'password123');
    await page2.click('[data-testid="login-button"]');

    // Create booking in first tab
    const booking1Promise = (async () => {
      await page.click('[data-testid="create-booking-button"]');
      await page.fill('[data-testid="resource-select"]', 'Workshop G');
      await page.fill('[data-testid="start-time-input"]', '2024-02-28T15:00');
      await page.fill('[data-testid="end-time-input"]', '2024-02-28T16:00');
      await page.click('[data-testid="save-booking-button"]');
    })();

    // Create overlapping booking in second tab simultaneously
    const booking2Promise = (async () => {
      await page2.click('[data-testid="create-booking-button"]');
      await page2.fill('[data-testid="resource-select"]', 'Workshop G');
      await page2.fill('[data-testid="start-time-input"]', '2024-02-28T15:30');
      await page2.fill('[data-testid="end-time-input"]', '2024-02-28T16:30');
      await page2.click('[data-testid="save-booking-button"]');
    })();

    // Wait for both requests to complete
    await Promise.all([booking1Promise, booking2Promise]);

    // Verify one succeeded and one detected conflict
    const successVisible = await page.locator('[data-testid="success-message"]').isVisible().catch(() => false);
    const conflictVisible = await page2.locator('[data-testid="conflict-alert"]').isVisible().catch(() => false);
    
    expect(successVisible || conflictVisible).toBeTruthy();
    
    // Check conflict log shows the conflict was detected
    await page.click('[data-testid="view-conflicts-button"]');
    await expect(page.locator('[data-testid="conflict-log-entry"]').filter({ hasText: 'Workshop G' })).toBeVisible();
    
    await page2.close();
  });

  test('should detect partial overlap at start of existing booking', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Classroom H');
    await page.fill('[data-testid="start-time-input"]', '2024-03-01T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-03-01T12:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create booking overlapping at start
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Classroom H');
    await page.fill('[data-testid="start-time-input"]', '2024-03-01T09:00');
    await page.fill('[data-testid="end-time-input"]', '2024-03-01T10:30');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify conflict detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Overlapping booking detected');
  });

  test('should detect partial overlap at end of existing booking', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Library I');
    await page.fill('[data-testid="start-time-input"]', '2024-03-05T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-03-05T16:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create booking overlapping at end
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Library I');
    await page.fill('[data-testid="start-time-input"]', '2024-03-05T15:30');
    await page.fill('[data-testid="end-time-input"]', '2024-03-05T17:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify conflict detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Overlapping booking detected');
  });

  test('should not detect conflict for different resources with same time', async ({ page }) => {
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Room J');
    await page.fill('[data-testid="start-time-input"]', '2024-03-10T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-03-10T11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create booking for different resource at same time
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Room K');
    await page.fill('[data-testid="start-time-input"]', '2024-03-10T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-03-10T11:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Verify no conflict detected
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
  });
});