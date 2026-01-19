import { test, expect } from '@playwright/test';

test.describe('Resource Availability Real-Time Display', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/dashboard');
  });

  test('Verify real-time resource availability display (happy-path)', async ({ page }) => {
    // Navigate to the scheduling interface from the main dashboard
    await page.click('[data-testid="scheduling-interface-link"]');
    await expect(page).toHaveURL(/.*scheduling/);

    // Select a specific resource from the resource list
    await page.click('[data-testid="resource-list"]');
    await page.click('[data-testid="resource-item-conference-room-a"]');

    // Verify the calendar shows existing bookings with time slots and booking details
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    const existingBookings = page.locator('[data-testid="booked-slot"]');
    await expect(existingBookings.first()).toBeVisible();
    await expect(page.locator('[data-testid="free-slot"]').first()).toBeVisible();

    // Create a new booking for the selected resource by choosing an available time slot and saving
    await page.click('[data-testid="free-slot"]:has-text("10:00 AM")');
    await page.fill('[data-testid="booking-title-input"]', 'Team Meeting');
    await page.fill('[data-testid="booking-duration-input"]', '60');
    await page.click('[data-testid="save-booking-button"]');

    // Observe the availability calendar without refreshing the page
    // Wait for real-time update (should be within 1 second)
    await page.waitForTimeout(1000);
    
    // Verify the previously free slot is now marked as booked
    await expect(page.locator('[data-testid="booked-slot"]:has-text("10:00 AM")')).toBeVisible({ timeout: 1000 });

    // Click on the resource type filter dropdown and select a specific resource type
    await page.click('[data-testid="resource-type-filter"]');
    await page.click('[data-testid="filter-option-conference-room"]');

    // Verify calendar updates to show filtered resources
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    const filteredResources = page.locator('[data-testid="resource-item"]');
    await expect(filteredResources.first()).toContainText('Conference Room');

    // Clear the filter or select a different resource type
    await page.click('[data-testid="resource-type-filter"]');
    await page.click('[data-testid="filter-option-all"]');
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
  });

  test('Ensure availability data refresh latency under 1 second (boundary)', async ({ page, context }) => {
    // Open the availability calendar for a specific resource in the scheduling interface
    await page.click('[data-testid="scheduling-interface-link"]');
    await page.click('[data-testid="resource-item-meeting-room-b"]');
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();

    // Count initial bookings
    const initialBookingCount = await page.locator('[data-testid="booked-slot"]').count();

    // Using an external method (API call) to create a new booking for the same resource
    const apiContext = await context.request;
    const startTime = Date.now();
    
    await apiContext.post('/api/bookings', {
      data: {
        resourceId: 'meeting-room-b',
        startTime: '2024-01-15T14:00:00Z',
        endTime: '2024-01-15T15:00:00Z',
        title: 'External Booking'
      }
    });

    // Observe the availability view in the original session without manual refresh
    await page.waitForSelector(`[data-testid="booked-slot"]:nth-child(${initialBookingCount + 1})`, { timeout: 1000 });
    const updateTime = Date.now() - startTime;

    // Verify update occurred within 1 second
    expect(updateTime).toBeLessThan(1000);

    // Externally modify an existing booking (change time or cancel) for the resource being viewed
    const modifyStartTime = Date.now();
    await apiContext.delete('/api/bookings/external-booking-id');

    // Observe the UI response time for the availability update
    await page.waitForTimeout(100);
    const updatedBookingCount = await page.locator('[data-testid="booked-slot"]').count();
    const modifyUpdateTime = Date.now() - modifyStartTime;

    // Verify no noticeable delay in availability display
    expect(modifyUpdateTime).toBeLessThan(1000);
    expect(updatedBookingCount).toBe(initialBookingCount);

    // Compare the displayed availability data with actual booking records via API query
    const apiBookings = await apiContext.get('/api/resources/meeting-room-b/availability');
    const apiData = await apiBookings.json();
    const displayedBookingCount = await page.locator('[data-testid="booked-slot"]').count();
    
    // Confirm data accuracy - displayed availability matches actual bookings
    expect(displayedBookingCount).toBe(apiData.bookings.length);

    // Perform multiple rapid external booking changes and monitor UI updates
    for (let i = 0; i < 3; i++) {
      await apiContext.post('/api/bookings', {
        data: {
          resourceId: 'meeting-room-b',
          startTime: `2024-01-15T${16 + i}:00:00Z`,
          endTime: `2024-01-15T${17 + i}:00:00Z`,
          title: `Rapid Booking ${i + 1}`
        }
      });
      await page.waitForTimeout(200);
    }

    const finalBookingCount = await page.locator('[data-testid="booked-slot"]').count();
    expect(finalBookingCount).toBeGreaterThan(initialBookingCount);
  });

  test('Test integration of availability view with scheduling form (happy-path)', async ({ page }) => {
    // Open the scheduling interface and display the availability calendar for a resource
    await page.click('[data-testid="scheduling-interface-link"]');
    await page.click('[data-testid="resource-item-lab-equipment-1"]');
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();

    // Click on an available (free) time slot in the availability calendar
    await page.click('[data-testid="free-slot"]:has-text("09:00 AM")');

    // Verify that the scheduling form pre-fills with selected resource and time
    await expect(page.locator('[data-testid="scheduling-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="resource-name-field"]')).toHaveValue('Lab Equipment 1');
    await expect(page.locator('[data-testid="date-field"]')).not.toBeEmpty();
    await expect(page.locator('[data-testid="start-time-field"]')).toHaveValue('09:00');
    await expect(page.locator('[data-testid="end-time-field"]')).not.toBeEmpty();

    // Navigate back to the availability calendar and click on a time slot that is already booked (unavailable)
    await page.click('[data-testid="back-to-calendar-button"]');
    await page.click('[data-testid="booked-slot"]').first();

    // Attempt to manually modify the scheduling form to book the unavailable slot
    await page.fill('[data-testid="start-time-field"]', '11:00');
    await page.fill('[data-testid="end-time-field"]', '12:00');
    await page.fill('[data-testid="booking-title-input"]', 'Conflicting Booking');
    await page.click('[data-testid="save-booking-button"]');

    // System prevents booking and displays conflict alert
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('unavailable');

    // Review the conflict alert message for clarity and actionable information
    const alertText = await page.locator('[data-testid="conflict-alert"]').textContent();
    expect(alertText).toBeTruthy();
    expect(alertText?.length).toBeGreaterThan(20);

    // Close the conflict alert
    await page.click('[data-testid="close-alert-button"]');

    // Select a different available time slot from the calendar and complete the booking form
    await page.click('[data-testid="back-to-calendar-button"]');
    await page.click('[data-testid="free-slot"]:has-text("02:00 PM")');
    await page.fill('[data-testid="booking-title-input"]', 'Valid Equipment Booking');
    await page.fill('[data-testid="booking-description-input"]', 'Testing equipment usage');

    // Submit the booking for the available slot
    await page.click('[data-testid="save-booking-button"]');

    // Booking succeeds without conflict
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully');

    // Verify the availability calendar updates to show the newly booked slot as unavailable
    await page.click('[data-testid="back-to-calendar-button"]');
    await expect(page.locator('[data-testid="booked-slot"]:has-text("02:00 PM")')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="booked-slot"]:has-text("Valid Equipment Booking")')).toBeVisible();
  });
});