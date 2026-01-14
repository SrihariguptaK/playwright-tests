import { test, expect } from '@playwright/test';

test.describe('Story-18: Prevent booking confirmation when conflicts exist', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling page
    await page.goto(`${BASE_URL}/schedule`);
  });

  test('Block booking confirmation when conflict exists - happy path', async ({ page, request }) => {
    // Step 1: Create or select a booking that has a scheduling conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-15T10:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-15T11:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Wait for booking to be created
    await expect(page.locator('[data-testid="booking-created-message"]')).toBeVisible();
    const conflictingBookingId = await page.locator('[data-testid="booking-id"]').textContent();

    // Step 2: Attempt to confirm the conflicting booking
    const confirmResponse = await request.post(`${API_URL}/schedule/confirm`, {
      data: {
        bookingId: conflictingBookingId
      }
    });

    // Step 3: Verify the system response blocks confirmation
    expect(confirmResponse.status()).toBe(409); // Conflict status code
    const responseBody = await confirmResponse.json();
    expect(responseBody.success).toBe(false);
    expect(responseBody.error).toContain('conflict');

    // Step 4: Review the error message returned by the system
    await page.click(`[data-testid="booking-item-${conflictingBookingId}"]`);
    await page.click('[data-testid="confirm-booking-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    const errorMessage = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorMessage).toContain('conflict');
    expect(errorMessage).toContain('Conference Room A');

    // Step 5: Verify the booking status remains unchanged
    const bookingStatus = await page.locator('[data-testid="booking-status"]').textContent();
    expect(bookingStatus).toBe('Pending');

    // Step 6: Resolve the conflict by modifying the booking
    await page.click('[data-testid="edit-booking-button"]');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-15T14:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-15T15:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-updated-message"]')).toBeVisible();

    // Step 7: Retry the confirmation with updated booking
    const retryConfirmResponse = await request.post(`${API_URL}/schedule/confirm`, {
      data: {
        bookingId: conflictingBookingId
      }
    });

    // Step 8: Verify the confirmation is successful
    expect(retryConfirmResponse.status()).toBe(200);
    const retryResponseBody = await retryConfirmResponse.json();
    expect(retryResponseBody.success).toBe(true);
    expect(retryResponseBody.message).toContain('confirmed');

    // Verify booking status updated in UI
    await page.reload();
    await page.click(`[data-testid="booking-item-${conflictingBookingId}"]`);
    const updatedStatus = await page.locator('[data-testid="booking-status"]').textContent();
    expect(updatedStatus).toBe('Confirmed');
  });

  test('Verify confirmation response time - boundary', async ({ page, request }) => {
    // Step 1: Prepare a valid booking confirmation request with no conflicts
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-resource-input"]', 'Conference Room B');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-16T09:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-16T10:00');
    await page.click('[data-testid="save-booking-button"]');
    
    await expect(page.locator('[data-testid="booking-created-message"]')).toBeVisible();
    const bookingId = await page.locator('[data-testid="booking-id"]').textContent();

    // Step 2: Record the timestamp before sending the confirmation request
    const startTime = Date.now();

    // Step 3: Submit booking confirmation request
    const confirmResponse = await request.post(`${API_URL}/schedule/confirm`, {
      data: {
        bookingId: bookingId
      }
    });

    // Step 4: Wait for and receive the response from the server
    await confirmResponse.body();

    // Step 5: Record the timestamp when the response is received
    const endTime = Date.now();

    // Step 6: Calculate the total response time
    const responseTime = endTime - startTime;

    // Step 7: Verify that the response time is under 2 seconds
    expect(responseTime).toBeLessThan(2000);

    // Step 8: Verify the booking confirmation was successful
    expect(confirmResponse.status()).toBe(200);
    const responseBody = await confirmResponse.json();
    expect(responseBody.success).toBe(true);
    expect(responseBody.message).toContain('confirmed');

    // Verify in UI
    await page.reload();
    await page.click(`[data-testid="booking-item-${bookingId}"]`);
    const bookingStatus = await page.locator('[data-testid="booking-status"]').textContent();
    expect(bookingStatus).toBe('Confirmed');
  });

  test('Block booking confirmation when conflict exists', async ({ page, request }) => {
    // Action 1: Attempt to confirm booking with conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-resource-input"]', 'Meeting Room 1');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-20T13:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-20T14:00');
    await page.click('[data-testid="save-booking-button"]');
    
    await expect(page.locator('[data-testid="booking-created-message"]')).toBeVisible();
    const bookingId = await page.locator('[data-testid="booking-id"]').textContent();

    await page.click(`[data-testid="booking-item-${bookingId}"]`);
    await page.click('[data-testid="confirm-booking-button"]');

    // Expected Result: System blocks confirmation and displays error
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    const errorText = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorText).toContain('conflict');
    
    const status = await page.locator('[data-testid="booking-status"]').textContent();
    expect(status).not.toBe('Confirmed');

    // Action 2: Resolve conflict and retry confirmation
    await page.click('[data-testid="edit-booking-button"]');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-20T16:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-20T17:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="booking-updated-message"]')).toBeVisible();

    await page.click('[data-testid="confirm-booking-button"]');

    // Expected Result: Booking confirmed successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const successText = await page.locator('[data-testid="success-message"]').textContent();
    expect(successText).toContain('confirmed');
    
    const confirmedStatus = await page.locator('[data-testid="booking-status"]').textContent();
    expect(confirmedStatus).toBe('Confirmed');
  });

  test('Verify confirmation response time', async ({ page, request }) => {
    // Action: Submit booking confirmation request
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="booking-resource-input"]', 'Training Room');
    await page.fill('[data-testid="booking-start-time"]', '2024-03-22T11:00');
    await page.fill('[data-testid="booking-end-time"]', '2024-03-22T12:00');
    await page.click('[data-testid="save-booking-button"]');
    
    await expect(page.locator('[data-testid="booking-created-message"]')).toBeVisible();
    const bookingId = await page.locator('[data-testid="booking-id"]').textContent();

    const startTime = Date.now();
    
    const response = await request.post(`${API_URL}/schedule/confirm`, {
      data: {
        bookingId: bookingId
      }
    });
    
    await response.body();
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Expected Result: Response received within 2 seconds
    expect(responseTime).toBeLessThan(2000);
    expect(response.status()).toBe(200);
    
    const responseBody = await response.json();
    expect(responseBody.success).toBe(true);
  });
});