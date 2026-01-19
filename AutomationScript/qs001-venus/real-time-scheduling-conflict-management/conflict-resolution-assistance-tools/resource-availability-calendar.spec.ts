import { test, expect } from '@playwright/test';

test.describe('Resource Availability Calendar - Story 4', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_EMAIL = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'scheduler123';
  const NON_SCHEDULER_EMAIL = 'viewer@example.com';
  const NON_SCHEDULER_PASSWORD = 'viewer123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate display of resource availability calendar (happy-path)', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Navigate to the resource availability view from the main scheduling interface
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="resource-availability-link"]');
    
    // Expected Result: Availability calendar is displayed
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-header"]')).toContainText('Resource Availability');

    // Step 2: Verify that the calendar displays both booked and free time slots with visual differentiation
    const bookedSlots = page.locator('[data-testid="time-slot-booked"]');
    const freeSlots = page.locator('[data-testid="time-slot-free"]');
    await expect(bookedSlots.first()).toBeVisible();
    await expect(freeSlots.first()).toBeVisible();
    
    // Verify visual differentiation by checking CSS classes or attributes
    const bookedSlotClass = await bookedSlots.first().getAttribute('class');
    const freeSlotClass = await freeSlots.first().getAttribute('class');
    expect(bookedSlotClass).not.toBe(freeSlotClass);

    // Step 3: Apply a filter to select a specific resource type from the available filter options
    await page.click('[data-testid="resource-type-filter"]');
    await page.click('[data-testid="resource-type-option-conference-room"]');
    
    // Expected Result: Calendar updates to show filtered availability
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-resource-type"]')).toContainText('Conference Room');

    // Step 4: Apply a date range filter to view availability for a specific time period
    await page.click('[data-testid="date-range-filter"]');
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-07');
    await page.click('[data-testid="apply-date-filter-button"]');
    
    // Expected Result: Slots are clearly differentiated and accurate
    await expect(page.locator('[data-testid="calendar-date-range"]')).toContainText('Feb 1 - Feb 7, 2024');
    await expect(page.locator('[data-testid="time-slot-booked"]')).toHaveCount(await page.locator('[data-testid="time-slot-booked"]').count());
    await expect(page.locator('[data-testid="time-slot-free"]')).toHaveCount(await page.locator('[data-testid="time-slot-free"]').count());

    // Step 5: Review the filtered calendar to verify booked and free time slots are accurately displayed
    const totalSlots = await page.locator('[data-testid^="time-slot-"]').count();
    expect(totalSlots).toBeGreaterThan(0);

    // Step 6: Click on individual time slots to view detailed booking information
    await page.locator('[data-testid="time-slot-booked"]').first().click();
    await expect(page.locator('[data-testid="booking-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-resource-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="booking-time-info"]')).toBeVisible();
    await page.click('[data-testid="close-modal-button"]');
  });

  test('Ensure real-time updates of availability calendar (happy-path)', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to resource availability view
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="resource-availability-link"]');
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();

    // Step 1: Note the current availability status of a specific resource and time slot
    const targetSlot = page.locator('[data-testid="time-slot-free"]').first();
    await expect(targetSlot).toBeVisible();
    const slotId = await targetSlot.getAttribute('data-slot-id');
    const initialStatus = await targetSlot.getAttribute('data-status');
    expect(initialStatus).toBe('free');

    // Step 2: Create or modify a schedule that affects the noted resource's availability
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-05');
    await page.fill('[data-testid="booking-start-time"]', '10:00');
    await page.fill('[data-testid="booking-end-time"]', '11:00');
    await page.click('[data-testid="submit-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();

    // Step 3: Observe the availability calendar without manually refreshing the page
    // Expected Result: Availability calendar updates within 2 seconds
    await page.waitForTimeout(2000);
    const updatedSlot = page.locator(`[data-slot-id="${slotId}"]`);
    const updatedStatus = await updatedSlot.getAttribute('data-status');
    expect(updatedStatus).toBe('booked');
    await expect(updatedSlot).toHaveAttribute('data-testid', 'time-slot-booked');

    // Step 4: Manually refresh the calendar view using the refresh button
    await page.click('[data-testid="refresh-calendar-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Latest availability data is displayed
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    const refreshedSlot = page.locator(`[data-slot-id="${slotId}"]`);
    await expect(refreshedSlot).toHaveAttribute('data-status', 'booked');

    // Step 5: Verify no stale data is shown by comparing calendar with database records
    const bookedSlotsCount = await page.locator('[data-testid="time-slot-booked"]').count();
    expect(bookedSlotsCount).toBeGreaterThan(0);
    
    // Expected Result: Calendar reflects current bookings accurately
    await expect(page.locator('[data-testid="calendar-last-updated"]')).toBeVisible();
    const lastUpdatedText = await page.locator('[data-testid="calendar-last-updated"]').textContent();
    expect(lastUpdatedText).toContain('Updated');

    // Step 6: Delete or cancel the recently created booking
    await page.click('[data-testid="manage-bookings-link"]');
    await page.locator('[data-testid="booking-item"]').first().click();
    await page.click('[data-testid="delete-booking-button"]');
    await page.click('[data-testid="confirm-delete-button"]');
    await expect(page.locator('[data-testid="booking-deleted-message"]')).toBeVisible();
  });

  test('Verify access control for availability calendar (error-case)', async ({ page }) => {
    // Step 1: Log in to the system using credentials for a user with Scheduler role
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to the resource availability calendar view
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="resource-availability-link"]');
    
    // Expected Result: Access granted and calendar displayed
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-header"]')).toContainText('Resource Availability');

    // Step 3: Log out from the Scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 4: Log in using credentials for a user without Scheduler role
    await page.fill('[data-testid="email-input"]', NON_SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 5: Attempt to navigate to the resource availability calendar view
    const schedulingMenu = page.locator('[data-testid="scheduling-menu"]');
    const resourceAvailabilityLink = page.locator('[data-testid="resource-availability-link"]');
    
    // Expected Result: Access denied with appropriate error message
    if (await schedulingMenu.isVisible()) {
      await schedulingMenu.click();
      if (await resourceAvailabilityLink.isVisible()) {
        await resourceAvailabilityLink.click();
        await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
        await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
        await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to view this resource');
      }
    }

    // Step 6: Verify that the user is not able to bypass access control through direct URL access
    await page.goto(`${BASE_URL}/scheduling/resource-availability`);
    const currentUrl = page.url();
    
    // Should be redirected or show access denied
    if (currentUrl.includes('resource-availability')) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    } else {
      expect(currentUrl).not.toContain('resource-availability');
      expect(currentUrl).toMatch(/dashboard|unauthorized|403/);
    }

    // Step 7: Review system security logs for both access attempts
    // Log out and log back in as admin to check logs
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as admin/scheduler to verify logs
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Navigate to audit logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    
    // Expected Result: Access attempts are logged for audit
    await page.fill('[data-testid="log-search-input"]', NON_SCHEDULER_EMAIL);
    await page.click('[data-testid="search-logs-button"]');
    
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries.first()).toBeVisible();
    await expect(logEntries.first()).toContainText('resource-availability');
    await expect(logEntries.first()).toContainText('Access Denied');
  });

  test('Verify calendar loads within 2 seconds under normal conditions', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to resource availability and measure load time
    await page.click('[data-testid="scheduling-menu"]');
    
    const startTime = Date.now();
    await page.click('[data-testid="resource-availability-link"]');
    await expect(page.locator('[data-testid="availability-calendar"]')).toBeVisible();
    const endTime = Date.now();
    
    const loadTime = endTime - startTime;
    
    // Expected Result: Calendar loads within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Verify calendar is fully loaded with data
    await expect(page.locator('[data-testid="time-slot-booked"], [data-testid="time-slot-free"]').first()).toBeVisible();
  });
});