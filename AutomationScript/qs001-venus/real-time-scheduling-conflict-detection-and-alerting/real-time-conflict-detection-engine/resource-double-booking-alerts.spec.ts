import { test, expect } from '@playwright/test';

test.describe('Resource Double-Booking Alerts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to booking creation page before each test
    await page.goto('/bookings/create');
    await expect(page).toHaveTitle(/Booking|Schedule/);
  });

  test('Validate detection of resource double-booking during booking creation', async ({ page }) => {
    // Step 1: Select a resource already booked for the selected time
    await page.click('[data-testid="resource-selector"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Select date and time that conflicts with existing booking
    await page.fill('[data-testid="booking-date"]', '2024-06-15');
    await page.selectOption('[data-testid="start-time"]', '09:00');
    await page.selectOption('[data-testid="end-time"]', '10:00');
    
    // Expected Result: System displays real-time double-booking alert
    await expect(page.locator('[data-testid="double-booking-alert"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="double-booking-alert"]')).toContainText(/already booked|conflict|double-booking/i);
    await expect(page.locator('[data-testid="double-booking-alert"]')).toContainText(/Conference Room A/i);
    
    // Step 2: Attempt to save the booking
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: System blocks saving and shows error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/cannot save|blocked|conflict/i);
    
    // Verify booking was not saved by checking we're still on the creation page
    await expect(page).toHaveURL(/\/bookings\/create/);
  });

  test('Verify booking creation succeeds when resource is available', async ({ page }) => {
    // Step 1: Select an available resource
    await page.click('[data-testid="resource-selector"]');
    await page.click('[data-testid="resource-option-meeting-room-b"]');
    
    // Select available date and time slot
    await page.fill('[data-testid="booking-date"]', '2024-06-15');
    await page.selectOption('[data-testid="start-time"]', '13:00');
    await page.selectOption('[data-testid="end-time"]', '14:00');
    
    // Expected Result: No conflict alerts are shown
    await expect(page.locator('[data-testid="double-booking-alert"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Complete all other required booking information
    await page.fill('[data-testid="booking-purpose"]', 'Team Planning Meeting');
    await page.fill('[data-testid="booking-attendees"]', 'John Doe, Jane Smith');
    await page.fill('[data-testid="booking-notes"]', 'Quarterly planning session');
    
    // Step 2: Submit the booking
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: Booking is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully created|saved|confirmed/i);
    
    // Verify redirect to bookings list or confirmation page
    await expect(page).toHaveURL(/\/bookings(?:\/list|\/confirmation|\/)/);
  });

  test('Ensure double-booking detection latency is under 1 second', async ({ page }) => {
    // Prepare timing measurement
    const startTime = Date.now();
    
    // Step 1: Select resource causing double-booking
    await page.click('[data-testid="resource-selector"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Select conflicting time slot
    await page.fill('[data-testid="booking-date"]', '2024-06-15');
    await page.selectOption('[data-testid="start-time"]', '09:00');
    await page.selectOption('[data-testid="end-time"]', '10:00');
    
    // Wait for alert to appear and measure time
    await page.waitForSelector('[data-testid="double-booking-alert"]', { state: 'visible' });
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Expected Result: Alert appears within 1 second
    expect(latency).toBeLessThan(1000);
    
    // Verify alert contains accurate resource and booking conflict details
    const alertText = await page.locator('[data-testid="double-booking-alert"]').textContent();
    expect(alertText).toMatch(/Conference Room A/i);
    expect(alertText).toMatch(/09:00|9:00 AM/);
    expect(alertText).toMatch(/10:00|10:00 AM/);
    expect(alertText).toMatch(/2024-06-15|June 15/);
  });
});