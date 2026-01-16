import { test, expect } from '@playwright/test';

test.describe('Resource Double Booking Detection', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/resources/booking`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate detection of double bookings for resources (happy-path)', async ({ page }) => {
    // Navigate to the resource booking interface
    await expect(page).toHaveURL(/.*resources\/booking/);
    
    // Select a resource type 'Equipment' from the resource type dropdown
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-equipment"]');
    await expect(page.locator('[data-testid="resource-type-dropdown"]')).toContainText('Equipment');
    
    // Select a specific resource 'Projector-001' from the equipment list
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-projector-001"]');
    await expect(page.locator('[data-testid="resource-select-dropdown"]')).toContainText('Projector-001');
    
    // Enter booking details: Date (tomorrow's date), Start time (1:00 PM), End time (3:00 PM), Purpose 'Team Presentation'
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="booking-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="booking-start-time"]', '13:00');
    await page.fill('[data-testid="booking-end-time"]', '15:00');
    await page.fill('[data-testid="booking-purpose"]', 'Team Presentation');
    
    // Click the 'Save' or 'Book Resource' button
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: Booking is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/saved successfully|booked successfully/i);
    
    // Navigate back to the resource booking interface to create a new booking
    await page.goto(`${baseURL}/resources/booking`);
    await page.waitForLoadState('networkidle');
    
    // Select the same resource type 'Equipment' and the same resource 'Projector-001'
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-equipment"]');
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-projector-001"]');
    
    // Enter overlapping booking details: Same date (tomorrow), Start time (2:00 PM), End time (4:00 PM), Purpose 'Client Meeting'
    await page.fill('[data-testid="booking-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="booking-start-time"]', '14:00');
    await page.fill('[data-testid="booking-end-time"]', '16:00');
    await page.fill('[data-testid="booking-purpose"]', 'Client Meeting');
    
    // Click the 'Save' or 'Book Resource' button
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: System detects double booking and alerts the Resource Manager
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText(/double booking|conflict detected|already booked/i);
    
    // Review the conflict alert details displayed on screen
    const alertDetails = page.locator('[data-testid="conflict-details"]');
    await expect(alertDetails).toBeVisible();
    
    // Expected Result: Alert shows accurate conflicting booking information
    await expect(alertDetails).toContainText('Projector-001');
    await expect(alertDetails).toContainText('Team Presentation');
    await expect(alertDetails).toContainText(/13:00|1:00 PM/);
    await expect(alertDetails).toContainText(/15:00|3:00 PM/);
    
    // Verify that the overlapping booking was not saved to the schedule
    await page.click('[data-testid="close-alert-button"]');
    
    // Check the resource availability calendar for Projector-001
    await page.click('[data-testid="view-calendar-button"]');
    const calendarBookings = page.locator('[data-testid="calendar-booking-item"]');
    await expect(calendarBookings).toHaveCount(1);
    await expect(calendarBookings.first()).toContainText('Team Presentation');
    await expect(calendarBookings.filter({ hasText: 'Client Meeting' })).toHaveCount(0);
  });

  test('Verify real-time detection latency under 2 seconds (boundary)', async ({ page }) => {
    // Navigate to the resource booking interface
    await expect(page).toHaveURL(/.*resources\/booking/);
    
    // Create a baseline booking: Select resource 'Meeting Room B', Date (next Monday), Start time (10:00 AM), End time (11:30 AM)
    const nextMonday = new Date();
    nextMonday.setDate(nextMonday.getDate() + ((1 + 7 - nextMonday.getDay()) % 7 || 7));
    const nextMondayFormatted = nextMonday.toISOString().split('T')[0];
    
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-room"]');
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-meeting-room-b"]');
    
    await page.fill('[data-testid="booking-date-input"]', nextMondayFormatted);
    await page.fill('[data-testid="booking-start-time"]', '10:00');
    await page.fill('[data-testid="booking-end-time"]', '11:30');
    await page.fill('[data-testid="booking-purpose"]', 'Baseline Meeting');
    
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    
    // Prepare for timing measurement - navigate back to create conflicting booking
    await page.goto(`${baseURL}/resources/booking`);
    await page.waitForLoadState('networkidle');
    
    // Create a conflicting booking: Select same resource 'Meeting Room B', Date (next Monday), Start time (11:00 AM), End time (12:00 PM)
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-room"]');
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-meeting-room-b"]');
    
    await page.fill('[data-testid="booking-date-input"]', nextMondayFormatted);
    await page.fill('[data-testid="booking-start-time"]', '11:00');
    await page.fill('[data-testid="booking-end-time"]', '12:00');
    await page.fill('[data-testid="booking-purpose"]', 'Conflicting Meeting');
    
    // Start timing and click Save button
    const startTime = Date.now();
    
    // Listen for the conflict detection API call
    const responsePromise = page.waitForResponse(
      response => (response.url().includes('/resources/bookings') || response.url().includes('/resources/conflicts')) && 
                  (response.status() === 200 || response.status() === 409),
      { timeout: 3000 }
    );
    
    await page.click('[data-testid="save-booking-button"]');
    
    // Wait for conflict alert to appear and measure time
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    const endTime = Date.now();
    const detectionLatency = endTime - startTime;
    
    // Expected Result: Detection completes within 2 seconds
    expect(detectionLatency).toBeLessThan(2000);
    console.log(`Conflict detection latency: ${detectionLatency}ms`);
    
    // Verify API response timing
    const response = await responsePromise;
    expect(response.status()).toBeTruthy();
    
    // Test modification scenario - edit existing booking to create conflict
    await page.click('[data-testid="close-alert-button"]');
    await page.goto(`${baseURL}/resources/bookings`);
    
    // Find and edit the baseline booking
    await page.click('[data-testid="booking-item"]:has-text("Baseline Meeting")');
    await page.click('[data-testid="edit-booking-button"]');
    
    // Extend end time to create conflict (change 11:30 to 12:00)
    await page.fill('[data-testid="booking-end-time"]', '12:00');
    
    const modifyStartTime = Date.now();
    const modifyResponsePromise = page.waitForResponse(
      response => response.url().includes('/resources/bookings'),
      { timeout: 3000 }
    );
    
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    const modifyEndTime = Date.now();
    const modifyLatency = modifyEndTime - modifyStartTime;
    
    expect(modifyLatency).toBeLessThan(2000);
    console.log(`Modification conflict detection latency: ${modifyLatency}ms`);
    
    await modifyResponsePromise;
  });

  test('Ensure logging of resource booking conflicts (happy-path)', async ({ page }) => {
    // Navigate to the resource booking interface
    await expect(page).toHaveURL(/.*resources\/booking/);
    
    // Create a first booking: Select Resource Type 'Room', Resource 'Training Room 3', Date (next Friday)
    const nextFriday = new Date();
    nextFriday.setDate(nextFriday.getDate() + ((5 + 7 - nextFriday.getDay()) % 7 || 7));
    const nextFridayFormatted = nextFriday.toISOString().split('T')[0];
    
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-room"]');
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-training-room-3"]');
    
    await page.fill('[data-testid="booking-date-input"]', nextFridayFormatted);
    await page.fill('[data-testid="booking-start-time"]', '14:00');
    await page.fill('[data-testid="booking-end-time"]', '16:00');
    await page.fill('[data-testid="booking-purpose"]', 'Training Session');
    
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    
    // Note the current system timestamp before triggering the conflict
    const conflictTimestamp = new Date();
    const timestampBefore = conflictTimestamp.toISOString();
    
    // Navigate back to create double booking
    await page.goto(`${baseURL}/resources/booking`);
    await page.waitForLoadState('networkidle');
    
    // Attempt to create a double booking: Resource 'Training Room 3', Start time (3:00 PM), End time (5:00 PM)
    await page.click('[data-testid="resource-type-dropdown"]');
    await page.click('[data-testid="resource-type-room"]');
    await page.click('[data-testid="resource-select-dropdown"]');
    await page.click('[data-testid="resource-training-room-3"]');
    
    await page.fill('[data-testid="booking-date-input"]', nextFridayFormatted);
    await page.fill('[data-testid="booking-start-time"]', '15:00');
    await page.fill('[data-testid="booking-end-time"]', '17:00');
    await page.fill('[data-testid="booking-purpose"]', 'Workshop');
    
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: Conflict detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 3000 });
    
    // Read and acknowledge the conflict alert message
    const alertMessage = await page.locator('[data-testid="conflict-alert"]').textContent();
    expect(alertMessage).toBeTruthy();
    await page.click('[data-testid="close-alert-button"]');
    
    // Navigate to the conflict logs section
    await page.goto(`${baseURL}/reports/logs`);
    await page.waitForLoadState('networkidle');
    
    // Apply filters: Set date/time range, Resource Type 'Room', Conflict Type 'Double Booking'
    await page.click('[data-testid="log-filter-button"]');
    
    const filterStartDate = new Date(conflictTimestamp);
    filterStartDate.setHours(filterStartDate.getHours() - 1);
    const filterEndDate = new Date(conflictTimestamp);
    filterEndDate.setHours(filterEndDate.getHours() + 1);
    
    await page.fill('[data-testid="filter-start-date"]', filterStartDate.toISOString().slice(0, 16));
    await page.fill('[data-testid="filter-end-date"]', filterEndDate.toISOString().slice(0, 16));
    
    await page.click('[data-testid="filter-resource-type"]');
    await page.click('[data-testid="filter-resource-type-room"]');
    
    await page.click('[data-testid="filter-conflict-type"]');
    await page.click('[data-testid="filter-conflict-type-double-booking"]');
    
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');
    
    // Search for the log entry corresponding to the triggered double booking conflict
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toHaveCount(1, { timeout: 5000 });
    
    // Click on or expand the log entry to view full details
    await logEntries.first().click();
    await expect(page.locator('[data-testid="log-entry-details"]')).toBeVisible();
    
    const logDetails = page.locator('[data-testid="log-entry-details"]');
    
    // Verify the log entry contains the conflict timestamp
    await expect(logDetails.locator('[data-testid="log-timestamp"]')).toBeVisible();
    const logTimestampText = await logDetails.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestampText).toBeTruthy();
    
    // Verify the log entry contains resource information
    await expect(logDetails.locator('[data-testid="log-resource-info"]')).toContainText('Training Room 3');
    await expect(logDetails.locator('[data-testid="log-resource-type"]')).toContainText('Room');
    
    // Verify the log entry contains original booking details
    await expect(logDetails.locator('[data-testid="log-original-booking"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="log-original-booking"]')).toContainText('Training Session');
    await expect(logDetails.locator('[data-testid="log-original-booking"]')).toContainText(/14:00|2:00 PM/);
    await expect(logDetails.locator('[data-testid="log-original-booking"]')).toContainText(/16:00|4:00 PM/);
    
    // Verify the log entry contains conflicting booking attempt details
    await expect(logDetails.locator('[data-testid="log-conflicting-booking"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="log-conflicting-booking"]')).toContainText('Workshop');
    await expect(logDetails.locator('[data-testid="log-conflicting-booking"]')).toContainText(/15:00|3:00 PM/);
    await expect(logDetails.locator('[data-testid="log-conflicting-booking"]')).toContainText(/17:00|5:00 PM/);
    
    // Verify the log entry contains user information
    await expect(logDetails.locator('[data-testid="log-user-info"]')).toBeVisible();
    const userInfo = await logDetails.locator('[data-testid="log-user-info"]').textContent();
    expect(userInfo).toBeTruthy();
    
    // Verify the log entry contains conflict resolution status
    await expect(logDetails.locator('[data-testid="log-resolution-status"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="log-resolution-status"]')).toContainText(/rejected|prevented|blocked/i);
    
    // Export or print the log entry for documentation
    await page.click('[data-testid="export-log-button"]');
    const downloadPromise = page.waitForEvent('download', { timeout: 5000 });
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/log|conflict|export/i);
  });
});