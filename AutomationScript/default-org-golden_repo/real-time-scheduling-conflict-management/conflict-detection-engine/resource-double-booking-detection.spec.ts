import { test, expect } from '@playwright/test';

test.describe('Resource Double-Booking Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Resource Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'resource.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Detect resource double-booking on creation (happy-path)', async ({ page }) => {
    // Navigate to the resource booking creation page
    await page.goto('/resources/bookings/create');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Select Conference Room A as the resource
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await expect(page.locator('[data-testid="resource-select"]')).toContainText('Conference Room A');

    // Enter booking details that overlap with the existing booking (e.g., start time 2:30 PM, end time 3:30 PM)
    await page.fill('[data-testid="booking-title-input"]', 'Team Meeting');
    await page.fill('[data-testid="booking-date-input"]', '2024-03-15');
    await page.fill('[data-testid="booking-start-time-input"]', '14:30');
    await page.fill('[data-testid="booking-end-time-input"]', '15:30');

    // Click 'Save' or 'Create Booking' button
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: System flags the new booking as conflicting
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('resource double-booking detected');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Conference Room A');

    // Attempt to save the booking without making changes
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: System prevents saving and displays conflict warning
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot save booking with conflicts');
    const bookingUrl = page.url();
    expect(bookingUrl).toContain('/create');

    // Adjust the booking time to a non-overlapping slot (e.g., change to 3:30 PM - 4:30 PM)
    await page.fill('[data-testid="booking-start-time-input"]', '15:30');
    await page.fill('[data-testid="booking-end-time-input"]', '16:30');

    // Click 'Save' or 'Create Booking' button
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: Booking is saved successfully without conflict
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Booking created successfully');
    await expect(page).toHaveURL(/.*bookings/);
    await expect(page.locator('[data-testid="conflict-warning"]')).not.toBeVisible();
  });

  test('Detect resource double-booking on update (happy-path)', async ({ page }) => {
    // Navigate to the resource booking list and select Booking B (Conference Room A, 4:00 PM - 5:00 PM) to edit
    await page.goto('/resources/bookings');
    await expect(page.locator('[data-testid="bookings-list"]')).toBeVisible();
    
    // Find and click on Booking B
    await page.click('[data-testid="booking-item-booking-b"]');
    await page.click('[data-testid="edit-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
    
    // Verify initial booking details
    await expect(page.locator('[data-testid="resource-select"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="booking-start-time-input"]')).toHaveValue('16:00');
    await expect(page.locator('[data-testid="booking-end-time-input"]')).toHaveValue('17:00');

    // Modify the booking time to overlap with Booking A (e.g., change start time to 2:30 PM, end time to 3:30 PM)
    await page.fill('[data-testid="booking-start-time-input"]', '14:30');
    await page.fill('[data-testid="booking-end-time-input"]', '15:30');

    // Click 'Save' or 'Update Booking' button
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: System flags the updated booking as conflicting
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('resource double-booking detected');

    // Attempt to save the updated booking without resolving the conflict
    await page.click('[data-testid="save-booking-button"]');

    // Expected Result: System prevents saving and displays conflict warning
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot save booking with conflicts');
    const editUrl = page.url();
    expect(editUrl).toContain('/edit');

    // Click 'Cancel' button to abandon the update
    await page.click('[data-testid="cancel-booking-button"]');

    // Expected Result: Original booking remains unchanged
    await expect(page).toHaveURL(/.*bookings/);
    await page.click('[data-testid="booking-item-booking-b"]');
    await expect(page.locator('[data-testid="booking-details-start-time"]')).toContainText('4:00 PM');
    await expect(page.locator('[data-testid="booking-details-end-time"]')).toContainText('5:00 PM');
    await expect(page.locator('[data-testid="booking-details-resource"]')).toContainText('Conference Room A');
  });

  test('Performance test for resource double-booking detection (boundary)', async ({ page }) => {
    // Record the current timestamp and create a new resource booking that overlaps with an existing booking
    await page.goto('/resources/bookings/create');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Select resource and enter overlapping booking details
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await page.fill('[data-testid="booking-title-input"]', 'Performance Test Booking');
    await page.fill('[data-testid="booking-date-input"]', '2024-03-15');
    await page.fill('[data-testid="booking-start-time-input"]', '14:30');
    await page.fill('[data-testid="booking-end-time-input"]', '15:30');

    // Click 'Save' button and measure the time until conflict detection message appears
    const startTime = Date.now();
    await page.click('[data-testid="save-booking-button"]');
    
    // Wait for conflict detection and measure elapsed time
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
    const endTime = Date.now();
    const elapsedTime = endTime - startTime;

    // Expected Result: System detects conflicts within 2 seconds
    expect(elapsedTime).toBeLessThan(2000);
    console.log(`Conflict detection time: ${elapsedTime}ms`);

    // Cancel the conflicting booking creation
    await page.click('[data-testid="cancel-booking-button"]');
    await expect(page).toHaveURL(/.*bookings/);

    // Initiate multiple concurrent resource booking creations (5-10 bookings) with varying overlap scenarios
    const concurrentBookings = [];
    const performanceResults = [];

    for (let i = 0; i < 5; i++) {
      const bookingPromise = (async () => {
        const context = await page.context().browser()?.newContext();
        if (!context) return;
        const newPage = await context.newPage();
        
        // Login
        await newPage.goto('/login');
        await newPage.fill('[data-testid="username-input"]', 'resource.manager@company.com');
        await newPage.fill('[data-testid="password-input"]', 'password123');
        await newPage.click('[data-testid="login-button"]');
        
        // Create booking
        await newPage.goto('/resources/bookings/create');
        await newPage.click('[data-testid="resource-select"]');
        await newPage.click('[data-testid="resource-option-conference-room-a"]');
        await newPage.fill('[data-testid="booking-title-input"]', `Concurrent Booking ${i + 1}`);
        await newPage.fill('[data-testid="booking-date-input"]', '2024-03-15');
        await newPage.fill('[data-testid="booking-start-time-input"]', '14:30');
        await newPage.fill('[data-testid="booking-end-time-input"]', '15:30');
        
        const requestStartTime = Date.now();
        await newPage.click('[data-testid="save-booking-button"]');
        await expect(newPage.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 2000 });
        const requestEndTime = Date.now();
        const requestElapsedTime = requestEndTime - requestStartTime;
        
        performanceResults.push(requestElapsedTime);
        console.log(`Concurrent booking ${i + 1} conflict detection time: ${requestElapsedTime}ms`);
        
        await newPage.close();
        await context.close();
      })();
      
      concurrentBookings.push(bookingPromise);
    }

    // Wait for all concurrent bookings to complete
    await Promise.all(concurrentBookings);

    // Expected Result: System processes all conflict detections within SLA
    performanceResults.forEach((time, index) => {
      expect(time).toBeLessThan(2000);
      console.log(`Booking ${index + 1} met SLA: ${time}ms < 2000ms`);
    });

    const averageTime = performanceResults.reduce((a, b) => a + b, 0) / performanceResults.length;
    console.log(`Average conflict detection time: ${averageTime}ms`);
    expect(averageTime).toBeLessThan(2000);
  });
});