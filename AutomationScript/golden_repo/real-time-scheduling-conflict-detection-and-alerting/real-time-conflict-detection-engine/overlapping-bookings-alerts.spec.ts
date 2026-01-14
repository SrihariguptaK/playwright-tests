import { test, expect } from '@playwright/test';

test.describe('Overlapping Bookings Alert System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling system and login as scheduler
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection of overlapping bookings', async ({ page }) => {
    // Step 1: Navigate to the booking creation page
    await page.goto(`${BASE_URL}/bookings/create`);
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Step 2: Enter booking details that overlap with existing booking
    await page.fill('[data-testid="resource-input"]', 'Resource A');
    await page.fill('[data-testid="start-time-input"]', '10:30 AM');
    await page.fill('[data-testid="end-time-input"]', '11:30 AM');
    await page.fill('[data-testid="booking-date-input"]', new Date().toISOString().split('T')[0]);
    
    // Step 3: Submit the booking request
    const startTime = Date.now();
    await page.click('[data-testid="create-booking-button"]');
    
    // Expected Result: System detects conflict within 1 second
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 1000 });
    const detectionTime = Date.now() - startTime;
    expect(detectionTime).toBeLessThan(1000);

    // Step 4: Verify scheduler receives detailed conflict alert
    await expect(conflictAlert).toContainText('Conflict Detected');
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-resource"]')).toContainText('Resource A');
    await expect(page.locator('[data-testid="conflict-time"]')).toContainText('10:30 AM');

    // Step 5: Attempt to confirm booking while conflict is unresolved
    const confirmButton = page.locator('[data-testid="confirm-booking-button"]');
    await expect(confirmButton).toBeDisabled();
    
    // Verify booking is not saved
    await page.goto(`${BASE_URL}/bookings`);
    const bookingsList = page.locator('[data-testid="bookings-list"]');
    await expect(bookingsList).not.toContainText('10:30 AM - 11:30 AM');
  });

  test('Verify conflict logging', async ({ page }) => {
    // Step 1: Navigate to the booking creation page
    await page.goto(`${BASE_URL}/bookings/create`);
    
    // Step 2: Create a booking that conflicts with existing booking
    await page.fill('[data-testid="resource-input"]', 'Resource A');
    await page.fill('[data-testid="start-time-input"]', '10:30 AM');
    await page.fill('[data-testid="end-time-input"]', '11:30 AM');
    await page.fill('[data-testid="booking-date-input"]', new Date().toISOString().split('T')[0]);
    
    // Note the timestamp before creating conflict
    const conflictTimestamp = new Date();
    
    // Step 3: Submit and observe conflict detection
    await page.click('[data-testid="create-booking-button"]');
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    
    // Step 4: Navigate to conflict logs section
    await page.goto(`${BASE_URL}/admin/conflict-logs`);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();
    
    // Step 5: Search for recently created conflict event
    await page.fill('[data-testid="log-search-input"]', 'Resource A');
    await page.click('[data-testid="search-button"]');
    
    // Step 6: Verify conflict event is logged with timestamp and user info
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-user"]')).toContainText('scheduler@example.com');
    await expect(logEntry.locator('[data-testid="log-resource"]')).toContainText('Resource A');
    await expect(logEntry.locator('[data-testid="log-time-range"]')).toContainText('10:30 AM');
    
    // Step 7: Verify completeness and accuracy of logged information
    await logEntry.click();
    await expect(page.locator('[data-testid="log-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-detail-resource"]')).toContainText('Resource A');
    await expect(page.locator('[data-testid="log-detail-conflict-type"]')).toContainText('Overlapping Booking');
    await expect(page.locator('[data-testid="log-detail-user-id"]')).not.toBeEmpty();
  });

  test('Test alert UI display', async ({ page }) => {
    // Step 1: Navigate to the booking creation page
    await page.goto(`${BASE_URL}/bookings/create`);
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
    
    // Step 2: Enter booking details that will trigger a conflict
    await page.fill('[data-testid="resource-input"]', 'Resource A');
    await page.fill('[data-testid="start-time-input"]', '10:30 AM');
    await page.fill('[data-testid="end-time-input"]', '11:30 AM');
    await page.fill('[data-testid="booking-date-input"]', new Date().toISOString().split('T')[0]);
    
    // Step 3: Submit the booking to trigger conflict detection
    await page.click('[data-testid="create-booking-button"]');
    
    // Step 4: Observe the alert UI component
    const alertUI = page.locator('[data-testid="conflict-alert"]');
    await expect(alertUI).toBeVisible();
    
    // Step 5: Verify alert UI styling and positioning
    await expect(alertUI).toHaveCSS('display', /block|flex/);
    const boundingBox = await alertUI.boundingBox();
    expect(boundingBox).not.toBeNull();
    expect(boundingBox!.y).toBeGreaterThan(0);
    
    // Verify alert contains conflict details
    await expect(alertUI.locator('[data-testid="alert-title"]')).toContainText('Conflict');
    await expect(alertUI.locator('[data-testid="conflict-details"]')).toBeVisible();
    
    // Step 6: Click on View Details button
    const viewDetailsButton = alertUI.locator('[data-testid="view-details-button"]');
    await expect(viewDetailsButton).toBeVisible();
    await viewDetailsButton.click();
    
    // Verify detailed conflict information is displayed
    const detailsModal = page.locator('[data-testid="conflict-details-modal"]');
    await expect(detailsModal).toBeVisible();
    await expect(detailsModal.locator('[data-testid="conflict-resource-detail"]')).toContainText('Resource A');
    await expect(detailsModal.locator('[data-testid="conflict-time-detail"]')).toContainText('10:30 AM');
    await expect(detailsModal.locator('[data-testid="existing-booking-info"]')).toBeVisible();
    
    // Close details modal
    await page.locator('[data-testid="close-details-modal"]').click();
    await expect(detailsModal).not.toBeVisible();
    
    // Step 7: Click on Acknowledge button
    const acknowledgeButton = alertUI.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();
    
    // Step 8: Verify alert can be dismissed or closed
    await expect(alertUI).not.toBeVisible();
    
    // Verify booking form is still accessible after dismissing alert
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();
  });
});