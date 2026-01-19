import { test, expect } from '@playwright/test';

test.describe('Story-9: Detailed Conflict Metadata', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify detailed conflict metadata display (happy-path)', async ({ page }) => {
    // Navigate to scheduling page
    await page.goto('/scheduling');
    await page.waitForLoadState('networkidle');

    // Create a new schedule for Conference Room A on 2024-01-15 from 2:30 PM to 3:30 PM (overlapping with existing booking)
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-01-15');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.fill('[data-testid="booking-title-input"]', 'Team Meeting');

    // Submit the conflicting schedule
    await page.click('[data-testid="submit-schedule-button"]');

    // Review the conflict alert message for metadata completeness
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 5000 });

    // Verify the alert displays the user who created the existing conflicting booking
    const conflictUser = conflictAlert.locator('[data-testid="conflict-user"]');
    await expect(conflictUser).toBeVisible();
    await expect(conflictUser).not.toBeEmpty();

    // Check if the alert includes descriptions or titles of both bookings
    const bookingTitles = conflictAlert.locator('[data-testid="booking-title"]');
    await expect(bookingTitles).toHaveCount(2);

    // Navigate to the conflicts dashboard or conflict management section
    await page.click('[data-testid="conflicts-dashboard-link"]');
    await expect(page).toHaveURL(/.*conflicts/);

    // Locate the recently triggered conflict in the dashboard
    const conflictEntry = page.locator('[data-testid="conflict-entry"]').first();
    await expect(conflictEntry).toBeVisible();

    // Click on the conflict entry to view detailed metadata
    await conflictEntry.click();

    // Verify metadata includes both booking IDs
    const bookingId1 = page.locator('[data-testid="booking-id-1"]');
    const bookingId2 = page.locator('[data-testid="booking-id-2"]');
    await expect(bookingId1).toBeVisible();
    await expect(bookingId2).toBeVisible();
    await expect(bookingId1).toHaveText(/BKG-\d+/);
    await expect(bookingId2).toHaveText(/BKG-\d+/);

    // Verify metadata includes complete resource information
    const resourceInfo = page.locator('[data-testid="resource-info"]');
    await expect(resourceInfo).toBeVisible();
    await expect(resourceInfo).toContainText('Conference Room A');

    // Verify metadata includes accurate timestamps
    const timestamp1 = page.locator('[data-testid="timestamp-1"]');
    const timestamp2 = page.locator('[data-testid="timestamp-2"]');
    await expect(timestamp1).toBeVisible();
    await expect(timestamp2).toBeVisible();
    await expect(timestamp1).toContainText('2024-01-15');
    await expect(timestamp2).toContainText('2024-01-15');

    // Check for conflict severity indicator in the metadata display
    const severityIndicator = page.locator('[data-testid="conflict-severity"]');
    await expect(severityIndicator).toBeVisible();

    // Verify the severity level matches the expected classification based on conflict type
    const severityText = await severityIndicator.textContent();
    expect(['Low', 'Medium', 'High', 'Critical']).toContain(severityText?.trim());

    // Check if metadata includes overlap duration information
    const overlapDuration = page.locator('[data-testid="overlap-duration"]');
    await expect(overlapDuration).toBeVisible();
    await expect(overlapDuration).toContainText(/\d+\s*(minute|hour)/);
  });

  test('Test metadata retrieval performance (happy-path)', async ({ page, request }) => {
    // Prepare API request to GET /api/conflicts/details with valid conflict ID and authentication token
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    const conflictId = 'CONF-12345';

    // Start timer and send API request to retrieve conflict metadata
    const startTime = Date.now();
    const response = await request.get(`/api/conflicts/details?conflictId=${conflictId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    const endTime = Date.now();

    // Measure the response time from request initiation to complete response receipt
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(1000);

    // Verify HTTP status code of the response
    expect(response.status()).toBe(200);

    // Parse the response body to extract conflict metadata
    const responseData = await response.json();

    // Verify presence of booking IDs in the response
    expect(responseData).toHaveProperty('bookingId1');
    expect(responseData).toHaveProperty('bookingId2');
    expect(responseData.bookingId1).toBeTruthy();
    expect(responseData.bookingId2).toBeTruthy();

    // Verify presence of resource information in the response
    expect(responseData).toHaveProperty('resourceInfo');
    expect(responseData.resourceInfo).toHaveProperty('resourceId');
    expect(responseData.resourceInfo).toHaveProperty('resourceName');

    // Verify presence of timestamp fields in the response
    expect(responseData).toHaveProperty('timestamp1');
    expect(responseData).toHaveProperty('timestamp2');
    expect(responseData.timestamp1).toBeTruthy();
    expect(responseData.timestamp2).toBeTruthy();

    // Verify presence of conflict severity indicator in the response
    expect(responseData).toHaveProperty('severity');
    expect(responseData.severity).toBeTruthy();

    // Verify presence of user information for conflicting bookings
    expect(responseData).toHaveProperty('user1');
    expect(responseData).toHaveProperty('user2');
    expect(responseData.user1).toBeTruthy();
    expect(responseData.user2).toBeTruthy();

    // Validate data accuracy by comparing response data with database records
    expect(responseData.bookingId1).toMatch(/^BKG-\d+$/);
    expect(responseData.bookingId2).toMatch(/^BKG-\d+$/);

    // Verify no required fields are missing or null
    const requiredFields = ['bookingId1', 'bookingId2', 'resourceInfo', 'timestamp1', 'timestamp2', 'severity', 'user1', 'user2'];
    for (const field of requiredFields) {
      expect(responseData[field]).not.toBeNull();
      expect(responseData[field]).not.toBeUndefined();
    }

    // Repeat API request 5 times to verify consistent performance
    for (let i = 0; i < 5; i++) {
      const iterationStartTime = Date.now();
      const iterationResponse = await request.get(`/api/conflicts/details?conflictId=${conflictId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      });
      const iterationEndTime = Date.now();
      const iterationResponseTime = iterationEndTime - iterationStartTime;
      
      expect(iterationResponseTime).toBeLessThan(1000);
      expect(iterationResponse.status()).toBe(200);
    }

    // Prepare API request using unauthorized user credentials (user without scheduler role)
    const unauthorizedToken = 'invalid_token_12345';

    // Send API request to GET /api/conflicts/details with unauthorized credentials
    const unauthorizedResponse = await request.get(`/api/conflicts/details?conflictId=${conflictId}`, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify the response status code for unauthorized access
    expect([401, 403]).toContain(unauthorizedResponse.status());

    // Verify no conflict metadata is returned in the response body
    const unauthorizedData = await unauthorizedResponse.json();
    expect(unauthorizedData).not.toHaveProperty('bookingId1');
    expect(unauthorizedData).not.toHaveProperty('bookingId2');

    // Check system logs for unauthorized access attempt (via UI)
    await page.goto('/admin/logs');
    await page.fill('[data-testid="log-search-input"]', 'unauthorized access');
    await page.click('[data-testid="search-logs-button"]');
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('unauthorized');
  });
});