import { test, expect } from '@playwright/test';

test.describe('Story-19: View Shift Details', () => {
  test.beforeEach(async ({ page }) => {
    // Login as authenticated employee
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate display of shift details on hover or selection', async ({ page }) => {
    // Navigate to the schedule page
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');

    // Identify a shift displayed in the schedule view
    const firstShift = page.locator('[data-testid="shift-card"]').first();
    await expect(firstShift).toBeVisible();

    // Hover the mouse cursor over the identified shift
    const startTime = Date.now();
    await firstShift.hover();

    // Verify that all required shift details are present in the displayed information
    const shiftTooltip = page.locator('[data-testid="shift-tooltip"]');
    await expect(shiftTooltip).toBeVisible();
    
    // Verify shift details loaded within 2 seconds
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);

    // Verify required shift details are displayed
    await expect(shiftTooltip.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(shiftTooltip.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(shiftTooltip.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(shiftTooltip.locator('[data-testid="shift-role"]')).toBeVisible();

    // Move the mouse cursor away from the shift
    await page.mouse.move(0, 0);
    await expect(shiftTooltip).not.toBeVisible();

    // Click or tap directly on the same shift
    const clickStartTime = Date.now();
    await firstShift.click();

    // Verify the detailed shift information display includes all required fields
    const shiftDetailsModal = page.locator('[data-testid="shift-details-modal"]');
    await expect(shiftDetailsModal).toBeVisible();
    
    // Verify that the shift details loaded within the performance requirement
    const clickLoadTime = Date.now() - clickStartTime;
    expect(clickLoadTime).toBeLessThan(2000);

    // Verify all required fields in detailed view
    await expect(shiftDetailsModal.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(shiftDetailsModal.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(shiftDetailsModal.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(shiftDetailsModal.locator('[data-testid="shift-role"]')).toBeVisible();

    // Verify location and role have non-empty text content
    const locationText = await shiftDetailsModal.locator('[data-testid="shift-location"]').textContent();
    const roleText = await shiftDetailsModal.locator('[data-testid="shift-role"]').textContent();
    expect(locationText).toBeTruthy();
    expect(roleText).toBeTruthy();

    // Close the detailed shift information view
    await page.locator('[data-testid="close-shift-details"]').click();
    await expect(shiftDetailsModal).not.toBeVisible();

    // Test the same interaction with a different shift in the schedule
    const secondShift = page.locator('[data-testid="shift-card"]').nth(1);
    await expect(secondShift).toBeVisible();
    
    await secondShift.hover();
    await expect(shiftTooltip).toBeVisible();
    
    await secondShift.click();
    await expect(shiftDetailsModal).toBeVisible();
    await expect(shiftDetailsModal.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(shiftDetailsModal.locator('[data-testid="shift-role"]')).toBeVisible();
  });

  test('Verify access control for shift details', async ({ page, request }) => {
    // Obtain a valid shift ID from the system
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');
    
    const firstShift = page.locator('[data-testid="shift-card"]').first();
    const shiftId = await firstShift.getAttribute('data-shift-id') || '12345';

    // Construct a GET request without authentication token
    const unauthenticatedResponse = await request.get(`/api/schedules/details?shiftId=${shiftId}`, {
      headers: {
        // Explicitly no Authorization header
      }
    });

    // Verify the response status code indicates unauthorized access
    expect(unauthenticatedResponse.status()).toBe(401);

    // Verify the error response body contains appropriate error message
    const responseBody = await unauthenticatedResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|authentication required|access denied/i);

    // Verify that no shift details data is included in the error response
    expect(responseBody).not.toHaveProperty('location');
    expect(responseBody).not.toHaveProperty('role');
    expect(responseBody).not.toHaveProperty('startTime');
    expect(responseBody).not.toHaveProperty('endTime');

    // Attempt to access the shift details API with an invalid authentication token
    const invalidTokenResponse = await request.get(`/api/schedules/details?shiftId=${shiftId}`, {
      headers: {
        'Authorization': 'Bearer invalid_token_12345'
      }
    });

    // Verify that invalid token also returns unauthorized
    expect(invalidTokenResponse.status()).toBe(401);

    const invalidTokenBody = await invalidTokenResponse.json();
    expect(invalidTokenBody).toHaveProperty('error');

    // Verify that the API does not expose shift details through error messages or headers
    const responseHeaders = invalidTokenResponse.headers();
    const headerValues = Object.values(responseHeaders).join(' ');
    expect(headerValues).not.toMatch(/location|role|shift/i);
    expect(invalidTokenBody.error).not.toContain('location');
    expect(invalidTokenBody.error).not.toContain('role');

    // Attempt with expired token format
    const expiredTokenResponse = await request.get(`/api/schedules/details?shiftId=${shiftId}`, {
      headers: {
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.expired'
      }
    });

    expect(expiredTokenResponse.status()).toBe(401);
    const expiredTokenBody = await expiredTokenResponse.json();
    expect(expiredTokenBody).toHaveProperty('error');
    expect(expiredTokenBody).not.toHaveProperty('location');
    expect(expiredTokenBody).not.toHaveProperty('role');
  });
});