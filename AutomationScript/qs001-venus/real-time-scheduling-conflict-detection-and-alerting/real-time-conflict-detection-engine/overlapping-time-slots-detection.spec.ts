import { test, expect } from '@playwright/test';

test.describe('Real-time Detection of Overlapping Time Slots', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to booking creation page and ensure user is authenticated
    await page.goto(`${BASE_URL}/bookings/create`);
    // Wait for the booking form to be visible
    await page.waitForSelector('[data-testid="booking-form"]', { timeout: 5000 });
  });

  test('Validate detection of overlapping time slots during booking creation', async ({ page }) => {
    // Step 1: Verify booking form is displayed
    const bookingForm = page.locator('[data-testid="booking-form"]');
    await expect(bookingForm).toBeVisible();
    
    // Step 2: Select a resource that has an existing booking
    await page.locator('[data-testid="resource-select"]').click();
    await page.locator('[data-testid="resource-option-A"]').click();
    
    // Select a date
    await page.locator('[data-testid="booking-date-input"]').fill('2024-01-15');
    
    // Select overlapping time slot (10:30 AM to 11:30 AM when existing booking is 10:00 AM to 11:00 AM)
    await page.locator('[data-testid="start-time-input"]').fill('10:30');
    await page.locator('[data-testid="end-time-input"]').fill('11:30');
    
    // Wait for real-time conflict detection to trigger
    await page.waitForTimeout(500);
    
    // Verify conflict alert is displayed with details
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert).toContainText('overlapping');
    
    // Verify conflict details are shown
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toBeVisible();
    
    // Step 3: Attempt to save the booking
    const saveButton = page.locator('[data-testid="save-booking-button"]');
    await saveButton.click();
    
    // Verify system prevents saving and displays error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('cannot be saved');
    
    // Verify booking was not saved by checking we're still on the creation page
    await expect(page).toHaveURL(/\/bookings\/create/);
  });

  test('Verify booking creation succeeds when no conflicts exist', async ({ page }) => {
    // Step 1: Select a resource that is available
    await page.locator('[data-testid="resource-select"]').click();
    await page.locator('[data-testid="resource-option-B"]').click();
    
    // Select a date
    await page.locator('[data-testid="booking-date-input"]').fill('2024-01-15');
    
    // Select non-conflicting time slot (2:00 PM to 3:00 PM)
    await page.locator('[data-testid="start-time-input"]').fill('14:00');
    await page.locator('[data-testid="end-time-input"]').fill('15:00');
    
    // Wait for real-time validation
    await page.waitForTimeout(500);
    
    // Verify no conflict alerts are shown
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).not.toBeVisible();
    
    // Fill in other required booking details
    await page.locator('[data-testid="booking-description"]').fill('Team meeting');
    await page.locator('[data-testid="booking-attendees"]').fill('John Doe, Jane Smith');
    
    // Step 2: Submit the booking form
    const saveButton = page.locator('[data-testid="save-booking-button"]');
    await saveButton.click();
    
    // Verify booking is saved successfully
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('successfully');
    
    // Verify confirmation is displayed
    const confirmationDialog = page.locator('[data-testid="booking-confirmation"]');
    await expect(confirmationDialog).toBeVisible();
    
    // Verify redirect to bookings list or confirmation page
    await expect(page).toHaveURL(/\/bookings\/(list|confirmation)/);
  });

  test('Ensure conflict detection latency is under 1 second', async ({ page }) => {
    // Step 1: Start timing measurement
    const startTime = Date.now();
    
    // Select a resource and time slot that triggers conflict detection
    await page.locator('[data-testid="resource-select"]').click();
    await page.locator('[data-testid="resource-option-A"]').click();
    
    await page.locator('[data-testid="booking-date-input"]').fill('2024-01-15');
    
    // Select overlapping time slot
    await page.locator('[data-testid="start-time-input"]').fill('10:30');
    await page.locator('[data-testid="end-time-input"]').fill('11:30');
    
    // Wait for conflict alert to appear and measure time
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await conflictAlert.waitFor({ state: 'visible', timeout: 2000 });
    
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Verify latency is under 1 second (1000ms)
    expect(latency).toBeLessThan(1000);
    
    // Verify conflict alert contains accurate details
    await expect(conflictAlert).toBeVisible();
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toBeVisible();
    
    // Verify conflicting booking ID is displayed
    const conflictingBookingId = page.locator('[data-testid="conflicting-booking-id"]');
    await expect(conflictingBookingId).toBeVisible();
    
    // Verify conflicting time range is displayed
    const conflictingTimeRange = page.locator('[data-testid="conflicting-time-range"]');
    await expect(conflictingTimeRange).toBeVisible();
    await expect(conflictingTimeRange).toContainText('10:00');
  });
});