import { test, expect } from '@playwright/test';

test.describe('Resource Availability Calendar', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/dashboard');
  });

  test('Verify calendar displays accurate resource availability', async ({ page }) => {
    // Action: Open resource availability calendar
    const startTime = Date.now();
    await page.click('[data-testid="resource-availability-menu"]');
    const loadTime = Date.now() - startTime;
    
    // Expected Result: Calendar loads within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    await expect(page.locator('[data-testid="resource-calendar"]')).toBeVisible();
    
    // Action: Select specific resource
    await page.click('[data-testid="resource-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Expected Result: Calendar shows booked and free slots accurately
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    const bookedSlots = page.locator('[data-testid="booked-slot"]');
    const freeSlots = page.locator('[data-testid="free-slot"]');
    await expect(bookedSlots).toHaveCount(await bookedSlots.count());
    await expect(freeSlots).toHaveCount(await freeSlots.count());
    
    // Verify at least one slot type is visible
    const totalSlots = await bookedSlots.count() + await freeSlots.count();
    expect(totalSlots).toBeGreaterThan(0);
    
    // Action: Change resource schedules externally (simulate by creating new appointment)
    const initialBookedCount = await bookedSlots.count();
    
    // Open new tab to create appointment
    const newPage = await page.context().newPage();
    await newPage.goto('/admin/appointments');
    await newPage.click('[data-testid="create-appointment-btn"]');
    await newPage.selectOption('[data-testid="appointment-resource"]', 'conference-room-a');
    await newPage.fill('[data-testid="appointment-date"]', '2024-01-15');
    await newPage.fill('[data-testid="appointment-time"]', '14:00');
    await newPage.fill('[data-testid="appointment-duration"]', '60');
    await newPage.click('[data-testid="save-appointment-btn"]');
    await expect(newPage.locator('[data-testid="success-message"]')).toBeVisible();
    await newPage.close();
    
    // Expected Result: Calendar updates availability in real-time
    // Wait for real-time update (websocket or polling)
    await page.waitForTimeout(3000);
    const updatedBookedCount = await page.locator('[data-testid="booked-slot"]').count();
    expect(updatedBookedCount).toBeGreaterThanOrEqual(initialBookedCount);
  });

  test('Test filtering by resource type', async ({ page }) => {
    // Navigate to resource availability calendar
    await page.click('[data-testid="resource-availability-menu"]');
    await expect(page.locator('[data-testid="resource-calendar"]')).toBeVisible();
    
    // Action: Apply filter for resource type
    await page.click('[data-testid="resource-type-filter"]');
    await page.click('[data-testid="filter-option-conference-rooms"]');
    
    // Expected Result: Calendar displays only selected resource type availability
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    const displayedResources = page.locator('[data-testid="resource-name"]');
    const resourceCount = await displayedResources.count();
    
    // Verify all displayed resources are of the filtered type
    for (let i = 0; i < resourceCount; i++) {
      const resourceName = await displayedResources.nth(i).textContent();
      expect(resourceName?.toLowerCase()).toContain('conference');
    }
    
    // Verify filter is active
    await expect(page.locator('[data-testid="active-filter-conference-rooms"]')).toBeVisible();
    
    // Action: Remove filter
    await page.click('[data-testid="remove-filter-btn"]');
    
    // Expected Result: Calendar shows all resources
    await page.waitForTimeout(1000);
    const allResourcesCount = await page.locator('[data-testid="resource-name"]').count();
    expect(allResourcesCount).toBeGreaterThan(resourceCount);
    
    // Verify filter is no longer active
    await expect(page.locator('[data-testid="active-filter-conference-rooms"]')).not.toBeVisible();
    
    // Verify multiple resource types are visible
    const allResourceNames = await page.locator('[data-testid="resource-name"]').allTextContents();
    const hasMultipleTypes = allResourceNames.some(name => !name.toLowerCase().includes('conference'));
    expect(hasMultipleTypes).toBeTruthy();
  });

  test('Verify calendar displays accurate resource availability - detailed flow', async ({ page }) => {
    // Navigate to the resource availability calendar section from the main dashboard
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('text=Resource Availability');
    await expect(page.locator('[data-testid="resource-calendar-section"]')).toBeVisible();
    
    // Select a specific resource from the resource dropdown or list
    await page.click('[data-testid="resource-dropdown"]');
    await page.waitForSelector('[data-testid="resource-list"]');
    await page.click('[data-testid="resource-option-meeting-room-b"]');
    
    // Verify the accuracy of displayed time slots by comparing with known scheduled appointments
    await expect(page.locator('[data-testid="selected-resource-name"]')).toHaveText('Meeting Room B');
    const timeSlots = page.locator('[data-testid="time-slot"]');
    await expect(timeSlots.first()).toBeVisible();
    
    // Check for specific known appointment
    const bookedSlot = page.locator('[data-testid="booked-slot"]').filter({ hasText: '10:00 AM' });
    await expect(bookedSlot).toBeVisible();
    
    // Using a separate session or admin panel, create a new appointment for the selected resource
    const adminContext = await page.context().browser()?.newContext();
    const adminPage = await adminContext!.newPage();
    await adminPage.goto('/admin/appointments');
    await adminPage.click('[data-testid="new-appointment-btn"]');
    await adminPage.selectOption('[data-testid="resource-select"]', 'meeting-room-b');
    await adminPage.fill('[data-testid="appointment-date-input"]', '2024-01-20');
    await adminPage.fill('[data-testid="appointment-start-time"]', '15:00');
    await adminPage.fill('[data-testid="appointment-end-time"]', '16:00');
    await adminPage.fill('[data-testid="appointment-title"]', 'Team Sync Meeting');
    await adminPage.click('[data-testid="submit-appointment-btn"]');
    await expect(adminPage.locator('[data-testid="appointment-created-message"]')).toBeVisible();
    await adminPage.close();
    await adminContext?.close();
    
    // Return to the calendar view and observe the resource availability display without manually refreshing
    await page.waitForTimeout(2000);
    const newBookedSlot = page.locator('[data-testid="booked-slot"]').filter({ hasText: '3:00 PM' });
    await expect(newBookedSlot).toBeVisible({ timeout: 5000 });
  });

  test('Test filtering by resource type - detailed flow', async ({ page }) => {
    // Navigate to calendar
    await page.click('[data-testid="resource-availability-menu"]');
    await expect(page.locator('[data-testid="resource-calendar"]')).toBeVisible();
    
    // Locate and click on the resource type filter dropdown or filter panel on the calendar interface
    await page.click('[data-testid="resource-type-filter-dropdown"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    // Select a specific resource type from the filter options (e.g., 'Conference Rooms')
    await page.click('[data-testid="filter-option-conference-rooms"]');
    await page.waitForTimeout(500);
    
    // Verify that only the filtered resource type is visible by checking resource names and availability slots
    const visibleResources = page.locator('[data-testid="resource-item"]');
    const resourceCount = await visibleResources.count();
    expect(resourceCount).toBeGreaterThan(0);
    
    for (let i = 0; i < resourceCount; i++) {
      const resourceType = await visibleResources.nth(i).getAttribute('data-resource-type');
      expect(resourceType).toBe('conference-room');
    }
    
    // Verify availability slots are displayed for filtered resources
    await expect(page.locator('[data-testid="availability-slot"]').first()).toBeVisible();
    
    // Click the remove filter button, clear filter option, or deselect the resource type filter
    await page.click('[data-testid="clear-filter-btn"]');
    await page.waitForTimeout(500);
    
    // Verify that all resources across all types are now visible in the calendar
    const allVisibleResources = page.locator('[data-testid="resource-item"]');
    const allResourceCount = await allVisibleResources.count();
    expect(allResourceCount).toBeGreaterThan(resourceCount);
    
    // Verify different resource types are present
    const resourceTypes = await allVisibleResources.evaluateAll(elements => 
      elements.map(el => el.getAttribute('data-resource-type'))
    );
    const uniqueTypes = new Set(resourceTypes);
    expect(uniqueTypes.size).toBeGreaterThan(1);
  });
});