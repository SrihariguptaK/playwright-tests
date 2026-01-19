import { test, expect } from '@playwright/test';

test.describe('Resource Double-Booking Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application base URL
    await page.goto('/');
    // Assume user is already logged in or perform login here if needed
  });

  test('Validate detection of resource double-booking (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface
    await page.click('text=Schedule');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();

    // Step 2: Create first appointment with Conference Room A
    await page.click('[data-testid="new-appointment-btn"]');
    
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '13:00');
    await page.fill('[data-testid="end-time"]', '14:00');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="client-name"]', 'John Doe');
    await page.fill('[data-testid="appointment-details"]', 'Initial meeting');
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Wait for save confirmation
    await expect(page.locator('text=Appointment saved successfully')).toBeVisible();

    // Step 3: Attempt to create second appointment with same resource and time slot
    await page.click('[data-testid="new-appointment-btn"]');
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '13:00');
    await page.fill('[data-testid="end-time"]', '14:00');
    await page.selectOption('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="client-name"]', 'Jane Smith');
    await page.fill('[data-testid="appointment-details"]', 'Follow-up meeting');

    // Step 4: Verify double-booking detection within 1 second
    const startTime = Date.now();
    const alertLocator = page.locator('[data-testid="double-booking-alert"]');
    await expect(alertLocator).toBeVisible({ timeout: 1000 });
    const detectionTime = Date.now() - startTime;
    expect(detectionTime).toBeLessThan(1000);

    // Step 5: Verify detailed alert with resource and time details
    await expect(alertLocator).toContainText('Conference Room A');
    await expect(alertLocator).toContainText('13:00');
    await expect(alertLocator).toContainText('14:00');
    await expect(alertLocator).toContainText('double-booking');
  });

  test('Verify prevention of saving double-booked schedules without override (error-case)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface
    await page.click('text=Schedule');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();

    // Create first appointment with Meeting Room B
    await page.click('[data-testid="new-appointment-btn"]');
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '11:00');
    await page.fill('[data-testid="end-time"]', '12:00');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="client-name"]', 'Alice Johnson');
    await page.fill('[data-testid="appointment-details"]', 'Team sync');
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('text=Appointment saved successfully')).toBeVisible();

    // Step 2: Attempt to create conflicting appointment without override
    await page.click('[data-testid="new-appointment-btn"]');
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '11:00');
    await page.fill('[data-testid="end-time"]', '12:00');
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room B');
    await page.fill('[data-testid="client-name"]', 'Bob Williams');
    await page.fill('[data-testid="appointment-details"]', 'Client presentation');

    // Step 3: Attempt to save without override
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Verify system blocks save and shows error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot save schedule with double-booked resource');
    
    // Verify appointment was not saved
    await expect(page.locator('text=Appointment saved successfully')).not.toBeVisible();

    // Step 4: Resolve conflict by changing resource
    await page.selectOption('[data-testid="resource-select"]', 'Meeting Room C');
    
    // Step 5: Save schedule with resolved resource assignment
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('text=Appointment saved successfully')).toBeVisible();
  });

  test('Check logging of double-booking events (happy-path)', async ({ page }) => {
    // Step 1: Navigate to scheduling interface
    await page.click('text=Schedule');
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();

    // Create first appointment with Projector Unit 1
    await page.click('[data-testid="new-appointment-btn"]');
    const currentDate = new Date().toISOString().split('T')[0];
    const currentTime = new Date();
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '15:00');
    await page.fill('[data-testid="end-time"]', '16:00');
    await page.selectOption('[data-testid="resource-select"]', 'Projector Unit 1');
    await page.fill('[data-testid="client-name"]', 'Charlie Brown');
    await page.fill('[data-testid="appointment-details"]', 'Training session');
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('text=Appointment saved successfully')).toBeVisible();

    // Step 2: Trigger double-booking detection
    await page.click('[data-testid="new-appointment-btn"]');
    await page.fill('[data-testid="appointment-date"]', currentDate);
    await page.fill('[data-testid="start-time"]', '15:00');
    await page.fill('[data-testid="end-time"]', '16:00');
    await page.selectOption('[data-testid="resource-select"]', 'Projector Unit 1');
    await page.fill('[data-testid="client-name"]', 'Diana Prince');
    await page.fill('[data-testid="appointment-details"]', 'Workshop');

    // Verify double-booking alert appears (triggering the event)
    await expect(page.locator('[data-testid="double-booking-alert"]')).toBeVisible();

    // Step 3: Open admin interface to check logs
    await page.click('text=Admin');
    await page.click('text=Event Logs');
    await expect(page.locator('[data-testid="event-logs-section"]')).toBeVisible();

    // Step 4: Search for the double-booking event
    await page.fill('[data-testid="log-search-resource"]', 'Projector Unit 1');
    await page.fill('[data-testid="log-search-date"]', currentDate);
    await page.click('[data-testid="search-logs-btn"]');

    // Step 5: Review and verify logged event details
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Projector Unit 1');
    await expect(logEntry).toContainText('double-booking');
    await expect(logEntry).toContainText(currentDate);
    await expect(logEntry).toContainText('15:00');
    
    // Verify timestamp is present and recent
    const timestampLocator = logEntry.locator('[data-testid="log-timestamp"]');
    await expect(timestampLocator).toBeVisible();
    
    // Verify user information is logged
    const userLocator = logEntry.locator('[data-testid="log-user"]');
    await expect(userLocator).toBeVisible();
    
    // Verify event type is correctly logged
    await expect(logEntry.locator('[data-testid="log-event-type"]')).toContainText('DOUBLE_BOOKING_DETECTED');
  });
});