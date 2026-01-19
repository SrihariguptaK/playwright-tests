import { test, expect } from '@playwright/test';

test.describe('Story-21: Booking Form Mandatory Field Validation', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to booking creation form before each test
    await page.goto(`${BASE_URL}/bookings/create`);
    await page.waitForLoadState('networkidle');
  });

  test('Verify validation blocks booking submission with missing mandatory fields', async ({ page }) => {
    // Leave the 'Date' mandatory field empty and click or tab to the next field
    await page.locator('[data-testid="booking-date-field"]').click();
    await page.keyboard.press('Tab');
    
    // Verify inline error for Date field
    const dateError = page.locator('[data-testid="booking-date-error"]');
    await expect(dateError).toBeVisible();
    await expect(dateError).toContainText(/date.*required/i);

    // Leave the 'Time' mandatory field empty and click or tab to the next field
    await page.locator('[data-testid="booking-time-field"]').click();
    await page.keyboard.press('Tab');
    
    // Verify inline error for Time field
    const timeError = page.locator('[data-testid="booking-time-error"]');
    await expect(timeError).toBeVisible();
    await expect(timeError).toContainText(/time.*required/i);

    // Leave the 'Resource' mandatory field empty and click or tab to the next field
    await page.locator('[data-testid="booking-resource-field"]').click();
    await page.keyboard.press('Tab');
    
    // Verify inline error for Resource field
    const resourceError = page.locator('[data-testid="booking-resource-error"]');
    await expect(resourceError).toBeVisible();
    await expect(resourceError).toContainText(/resource.*required/i);

    // Leave the 'Attendees' mandatory field empty and click or tab to the next field
    await page.locator('[data-testid="booking-attendees-field"]').click();
    await page.keyboard.press('Tab');
    
    // Verify inline error for Attendees field
    const attendeesError = page.locator('[data-testid="booking-attendees-error"]');
    await expect(attendeesError).toBeVisible();
    await expect(attendeesError).toContainText(/attendees.*required/i);

    // Verify that all inline error messages are displayed simultaneously
    await expect(dateError).toBeVisible();
    await expect(timeError).toBeVisible();
    await expect(resourceError).toBeVisible();
    await expect(attendeesError).toBeVisible();

    // Set up network request listener to verify no API call is made
    let apiCallMade = false;
    page.on('request', request => {
      if (request.url().includes('/api/bookings') && request.method() === 'POST') {
        apiCallMade = true;
      }
    });

    // Attempt to click the 'Submit' or 'Create Booking' button
    const submitButton = page.locator('[data-testid="booking-submit-button"]');
    await submitButton.click();

    // Verify that a summary error message is displayed at the top of the form
    const summaryError = page.locator('[data-testid="booking-form-error-summary"]');
    await expect(summaryError).toBeVisible();
    await expect(summaryError).toContainText(/please.*complete.*required.*fields/i);

    // Wait a moment to ensure no API call was made
    await page.waitForTimeout(1000);
    
    // Verify that no API call to POST /api/bookings was made
    expect(apiCallMade).toBe(false);
  });

  test('Ensure booking submission succeeds when all mandatory fields are filled', async ({ page }) => {
    // Calculate tomorrow's date for valid future date
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];

    // Fill in the 'Date' mandatory field with a valid future date
    await page.locator('[data-testid="booking-date-field"]').fill(tomorrowFormatted);
    
    // Fill in the 'Time' mandatory field with a valid time slot
    await page.locator('[data-testid="booking-time-start-field"]').fill('10:00');
    await page.locator('[data-testid="booking-time-end-field"]').fill('11:00');
    
    // Select a valid resource from the 'Resource' mandatory field dropdown
    await page.locator('[data-testid="booking-resource-field"]').click();
    await page.locator('[data-testid="resource-option-conference-room-a"]').click();
    
    // Add at least one attendee in the 'Attendees' mandatory field
    await page.locator('[data-testid="booking-attendees-field"]').fill('john.doe@example.com');
    await page.keyboard.press('Enter');

    // Verify that no validation error messages are displayed on the form
    await expect(page.locator('[data-testid="booking-date-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="booking-time-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="booking-resource-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="booking-attendees-error"]')).not.toBeVisible();

    // Verify that the 'Submit' or 'Create Booking' button is enabled and clickable
    const submitButton = page.locator('[data-testid="booking-submit-button"]');
    await expect(submitButton).toBeEnabled();

    // Set up network request promise to wait for API call
    const responsePromise = page.waitForResponse(
      response => response.url().includes('/api/bookings') && response.status() === 201
    );

    // Click the 'Submit' or 'Create Booking' button
    await submitButton.click();

    // Wait for the system response
    const response = await responsePromise;
    expect(response.status()).toBe(201);

    // Verify success confirmation message is displayed
    const successMessage = page.locator('[data-testid="booking-success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText(/booking.*created.*successfully/i);

    // Verify that the booking appears in the scheduler's booking list or calendar view
    await page.goto(`${BASE_URL}/bookings`);
    await page.waitForLoadState('networkidle');
    
    const bookingList = page.locator('[data-testid="booking-list"]');
    await expect(bookingList).toContainText('Conference Room A');
    await expect(bookingList).toContainText('john.doe@example.com');
  });

  test('Test validation feedback latency under 500 milliseconds', async ({ page }) => {
    const validationLatencies: number[] = [];

    // Test Date field validation latency with invalid past date
    const dateField = page.locator('[data-testid="booking-date-field"]');
    const dateError = page.locator('[data-testid="booking-date-error"]');
    
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    const pastDateFormatted = pastDate.toISOString().split('T')[0];
    
    let startTime = Date.now();
    await dateField.fill(pastDateFormatted);
    await dateField.blur();
    await dateError.waitFor({ state: 'visible' });
    let latency = Date.now() - startTime;
    validationLatencies.push(latency);
    expect(latency).toBeLessThan(500);

    // Test Date field validation latency with empty field
    await dateField.clear();
    startTime = Date.now();
    await dateField.blur();
    await dateError.waitFor({ state: 'visible' });
    latency = Date.now() - startTime;
    validationLatencies.push(latency);
    expect(latency).toBeLessThan(500);

    // Test Time field validation latency with invalid format
    const timeField = page.locator('[data-testid="booking-time-start-field"]');
    const timeError = page.locator('[data-testid="booking-time-error"]');
    
    startTime = Date.now();
    await timeField.fill('invalid-time');
    await timeField.blur();
    await timeError.waitFor({ state: 'visible' });
    latency = Date.now() - startTime;
    validationLatencies.push(latency);
    expect(latency).toBeLessThan(500);

    // Test Attendees field validation latency with invalid email format
    const attendeesField = page.locator('[data-testid="booking-attendees-field"]');
    const attendeesError = page.locator('[data-testid="booking-attendees-error"]');
    
    startTime = Date.now();
    await attendeesField.fill('invalid-email-format');
    await attendeesField.blur();
    await attendeesError.waitFor({ state: 'visible' });
    latency = Date.now() - startTime;
    validationLatencies.push(latency);
    expect(latency).toBeLessThan(500);

    // Fill all mandatory fields with valid data and test submission validation
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await dateField.fill(tomorrowFormatted);
    await timeField.fill('10:00');
    await page.locator('[data-testid="booking-time-end-field"]').fill('11:00');
    await page.locator('[data-testid="booking-resource-field"]').click();
    await page.locator('[data-testid="resource-option-conference-room-a"]').click();
    await attendeesField.clear();
    await attendeesField.fill('valid.email@example.com');
    
    const submitButton = page.locator('[data-testid="booking-submit-button"]');
    startTime = Date.now();
    await submitButton.click();
    
    // Wait for either success message or validation feedback
    await Promise.race([
      page.locator('[data-testid="booking-success-message"]').waitFor({ state: 'visible' }),
      page.locator('[data-testid="booking-form-error-summary"]').waitFor({ state: 'visible' })
    ]);
    latency = Date.now() - startTime;
    validationLatencies.push(latency);
    expect(latency).toBeLessThan(500);

    // Verify maximum validation latency across all tests
    const maxLatency = Math.max(...validationLatencies);
    expect(maxLatency).toBeLessThan(500);
    
    console.log(`Validation latencies recorded: ${validationLatencies.join(', ')}ms`);
    console.log(`Maximum validation latency: ${maxLatency}ms`);
  });
});