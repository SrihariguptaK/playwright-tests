import { test, expect } from '@playwright/test';

test.describe('Story-17: Conflict Logging with Detailed Metadata', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
  const CONFLICT_LOGS_ENDPOINT = `${API_BASE_URL}/api/conflicts/logs`;
  const RESPONSE_TIME_THRESHOLD = 3000; // 3 seconds

  test('Verify conflict logging with metadata (happy-path)', async ({ page, request }) => {
    // Step 1: Create or trigger a scheduling conflict
    await page.goto('/scheduling');
    
    // Book a resource for a specific time slot
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="user-id-input"]', 'user-001');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Wait for first booking confirmation
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    
    // Attempt to book the same resource for the same time slot to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="user-id-input"]', 'user-002');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Expected Result: Conflict detected and logged
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible();
    const conflictMessage = await page.locator('[data-testid="conflict-detected-message"]').textContent();
    expect(conflictMessage).toContain('conflict');
    
    // Step 2: Verify that the conflict is logged in the conflict log database
    // Wait a moment for the conflict to be logged
    await page.waitForTimeout(1000);
    
    // Step 3: Send GET request to /api/conflicts/logs endpoint
    const startTime = Date.now();
    const response = await request.get(CONFLICT_LOGS_ENDPOINT, {
      headers: {
        'Authorization': 'Bearer admin-token',
        'Content-Type': 'application/json'
      }
    });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Step 4: Measure the response time of the API query
    expect(responseTime).toBeLessThan(RESPONSE_TIME_THRESHOLD);
    expect(response.status()).toBe(200);
    
    const logs = await response.json();
    expect(Array.isArray(logs)).toBeTruthy();
    expect(logs.length).toBeGreaterThan(0);
    
    // Step 5: Verify the completeness of logged metadata fields
    const latestLog = logs[logs.length - 1];
    
    // Expected Result: Conflict logged with timestamp, user, and resource details
    expect(latestLog).toHaveProperty('timestamp');
    expect(latestLog.timestamp).toBeTruthy();
    
    expect(latestLog).toHaveProperty('userId');
    expect(latestLog.userId).toBeTruthy();
    
    expect(latestLog).toHaveProperty('resourceId');
    expect(latestLog.resourceId).toContain('Conference Room A');
    
    expect(latestLog).toHaveProperty('bookingDetails');
    expect(latestLog.bookingDetails).toHaveProperty('startTime');
    expect(latestLog.bookingDetails).toHaveProperty('endTime');
    
    expect(latestLog).toHaveProperty('conflictStatus');
    expect(['detected', 'pending', 'resolved', 'unresolved']).toContain(latestLog.conflictStatus);
    
    // Expected Result: Logs returned with complete metadata within 3 seconds
    expect(latestLog).toHaveProperty('conflictType');
    expect(latestLog).toHaveProperty('detectedAt');
  });

  test('Test access control for conflict logs (error-case)', async ({ request, page }) => {
    // Step 1: Authenticate as a user without authorized role
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular-user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for login to complete
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();
    
    // Get the unauthorized user token from localStorage or cookies
    const unauthorizedToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || 'unauthorized-user-token';
    });
    
    // Step 2: Attempt to access conflict logs with unauthorized user
    const unauthorizedResponse = await request.get(CONFLICT_LOGS_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: Access denied
    expect(unauthorizedResponse.status()).toBe(403);
    
    const unauthorizedBody = await unauthorizedResponse.json();
    
    // Step 3: Verify that no conflict log data is returned
    expect(unauthorizedBody).not.toHaveProperty('logs');
    expect(unauthorizedBody).toHaveProperty('error');
    expect(unauthorizedBody.error).toMatch(/access denied|forbidden|unauthorized/i);
    
    // Step 4: Log out and authenticate as a user with authorized role
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    
    await page.fill('[data-testid="username-input"]', 'admin-user');
    await page.fill('[data-testid="password-input"]', 'admin-password');
    await page.click('[data-testid="login-button"]');
    
    // Wait for admin login to complete
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
    
    // Get the authorized admin token
    const authorizedToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || 'admin-token';
    });
    
    // Step 5: Send GET request with authorized credentials
    const authorizedResponse = await request.get(CONFLICT_LOGS_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${authorizedToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: Logs accessible
    expect(authorizedResponse.status()).toBe(200);
    
    const authorizedBody = await authorizedResponse.json();
    
    // Step 6: Verify the conflict logs are returned in the response
    expect(Array.isArray(authorizedBody)).toBeTruthy();
    expect(authorizedBody.length).toBeGreaterThanOrEqual(0);
    
    // Verify log structure if logs exist
    if (authorizedBody.length > 0) {
      const log = authorizedBody[0];
      expect(log).toHaveProperty('timestamp');
      expect(log).toHaveProperty('userId');
      expect(log).toHaveProperty('resourceId');
      expect(log).toHaveProperty('conflictStatus');
    }
  });
});