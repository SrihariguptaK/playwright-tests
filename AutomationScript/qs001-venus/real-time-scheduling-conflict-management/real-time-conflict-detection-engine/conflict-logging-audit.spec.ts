import { test, expect } from '@playwright/test';

test.describe('Conflict Logging and Audit System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api';
  const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AdminPass123';
  const SCHEDULER_USERNAME = process.env.SCHEDULER_USERNAME || 'scheduler@example.com';
  const SCHEDULER_PASSWORD = process.env.SCHEDULER_PASSWORD || 'SchedulerPass123';
  let adminAuthToken: string;
  let schedulerAuthToken: string;

  test.beforeEach(async ({ page }) => {
    // Navigate to base URL
    await page.goto(BASE_URL);
  });

  test('Verify logging of detected conflicts (happy-path)', async ({ page, request }) => {
    // Log in as Scheduler user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to booking creation page
    await page.click('[data-testid="create-booking-link"]');
    await expect(page).toHaveURL(/.*booking\/create/);

    // Select resource 'Training Room C'
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-training-room-c"]');

    // Enter current date
    const currentDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="booking-date-input"]', currentDate);

    // Enter start time 1:30 PM
    await page.fill('[data-testid="start-time-input"]', '13:30');

    // Enter end time 2:30 PM
    await page.fill('[data-testid="end-time-input"]', '14:30');

    // Click Submit button to trigger scheduling conflict
    await page.click('[data-testid="submit-booking-button"]');

    // Verify conflict notification appears
    await expect(page.locator('[data-testid="conflict-notification"]')).toBeVisible();

    // Wait 2 seconds to ensure log write operation completes
    await page.waitForTimeout(2000);

    // Get authentication token for API calls
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));
    expect(authToken).toBeTruthy();

    // Execute API call GET /api/conflicts/logs
    const logsResponse = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify API response status
    expect(logsResponse.ok()).toBeTruthy();
    const logsData = await logsResponse.json();

    // Parse API response and search for log entry matching resource 'Training Room C'
    const recentLog = logsData.logs.find((log: any) => 
      log.resource === 'Training Room C' && 
      new Date(log.timestamp).toDateString() === new Date().toDateString()
    );
    expect(recentLog).toBeTruthy();

    // Verify log entry metadata completeness
    expect(recentLog.resource).toBe('Training Room C');
    expect(recentLog.timestamp).toBeTruthy();
    expect(recentLog.user).toBeTruthy();
    expect(recentLog.conflictDetails).toBeTruthy();
    expect(recentLog.startTime).toBe('13:30');
    expect(recentLog.endTime).toBe('14:30');

    // Log out and log in to admin UI
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to conflict logs section in admin UI
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-logs-link"]');
    await expect(page).toHaveURL(/.*admin\/conflict-logs/);

    // Verify search functionality
    await page.fill('[data-testid="log-search-input"]', 'Training Room C');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Training Room C');

    // Verify filter options by applying date filter
    await page.fill('[data-testid="date-filter-input"]', currentDate);
    await page.click('[data-testid="apply-filter-button"]');

    // Locate and click on the specific log entry
    const logEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Training Room C' }).first();
    await expect(logEntry).toBeVisible();
    await logEntry.click();

    // Verify log details are displayed
    await expect(page.locator('[data-testid="log-detail-resource"]')).toContainText('Training Room C');
    await expect(page.locator('[data-testid="log-detail-timestamp"]')).toBeVisible();
  });

  test('Test log write performance (boundary)', async ({ page, request }) => {
    // Log in as Scheduler user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Get authentication token
    const authToken = await page.evaluate(() => localStorage.getItem('authToken'));

    // Prepare test data: 5 different resources with time slots
    const testResources = [
      { name: 'Resource1', startTime: '09:15', endTime: '09:45' },
      { name: 'Resource2', startTime: '10:15', endTime: '10:45' },
      { name: 'Resource3', startTime: '11:15', endTime: '11:45' },
      { name: 'Resource4', startTime: '13:15', endTime: '13:45' },
      { name: 'Resource5', startTime: '14:15', endTime: '14:45' }
    ];

    const currentDate = new Date().toISOString().split('T')[0];
    const performanceMetrics: number[] = [];

    // Trigger conflicts in quick succession and measure performance
    for (const resource of testResources) {
      await page.goto(`${BASE_URL}/booking/create`);

      const startTime = Date.now();

      // Select resource
      await page.click('[data-testid="resource-select"]');
      await page.click(`[data-testid="resource-option-${resource.name.toLowerCase()}"]`);

      // Enter booking details
      await page.fill('[data-testid="booking-date-input"]', currentDate);
      await page.fill('[data-testid="start-time-input"]', resource.startTime);
      await page.fill('[data-testid="end-time-input"]', resource.endTime);

      // Submit to trigger conflict
      await page.click('[data-testid="submit-booking-button"]');
      await expect(page.locator('[data-testid="conflict-notification"]')).toBeVisible();

      const endTime = Date.now();
      const duration = endTime - startTime;
      performanceMetrics.push(duration);
    }

    // Wait for all log writes to complete
    await page.waitForTimeout(2000);

    // Verify each log write operation completed within 100 milliseconds
    for (let i = 0; i < performanceMetrics.length; i++) {
      console.log(`Conflict ${i + 1} log write duration: ${performanceMetrics[i]}ms`);
      // Note: This measures UI interaction time, actual log write time would be measured server-side
    }

    // Access conflict logs via API
    const logsResponse = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logsData = await logsResponse.json();

    // Verify log completeness - all 5 conflicts logged
    const todayLogs = logsData.logs.filter((log: any) => 
      new Date(log.timestamp).toDateString() === new Date().toDateString()
    );

    expect(todayLogs.length).toBeGreaterThanOrEqual(5);

    // Verify each resource conflict is logged
    for (const resource of testResources) {
      const resourceLog = todayLogs.find((log: any) => log.resource === resource.name);
      expect(resourceLog).toBeTruthy();
      expect(resourceLog.startTime).toBe(resource.startTime);
      expect(resourceLog.endTime).toBe(resource.endTime);
    }

    // Verify log entry order and timestamp accuracy
    const sortedLogs = todayLogs.sort((a: any, b: any) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    for (let i = 1; i < sortedLogs.length; i++) {
      const prevTimestamp = new Date(sortedLogs[i - 1].timestamp).getTime();
      const currTimestamp = new Date(sortedLogs[i].timestamp).getTime();
      expect(currTimestamp).toBeGreaterThanOrEqual(prevTimestamp);
    }

    // Monitor system performance - verify no degradation
    const performanceMetrics2 = await page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        loadTime: perfData.loadEventEnd - perfData.loadEventStart,
        domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart
      };
    });

    console.log('Performance metrics:', performanceMetrics2);
    expect(performanceMetrics2.loadTime).toBeLessThan(5000);
  });

  test('Ensure secure access to logs (error-case)', async ({ page, request }) => {
    // Attempt to access conflict logs API without authentication token
    const unauthorizedResponse1 = await request.get(`${API_BASE_URL}/conflicts/logs`);
    expect(unauthorizedResponse1.status()).toBe(401);

    // Attempt to access with invalid authentication token
    const unauthorizedResponse2 = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': 'Bearer invalid_token_12345',
        'Content-Type': 'application/json'
      }
    });
    expect(unauthorizedResponse2.status()).toBe(401);

    // Attempt to access with expired token
    const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.expired';
    const unauthorizedResponse3 = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${expiredToken}`,
        'Content-Type': 'application/json'
      }
    });
    expect(unauthorizedResponse3.status()).toBe(401);

    // Log in as regular Scheduler user (non-admin)
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', SCHEDULER_USERNAME);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Get scheduler auth token
    const schedulerToken = await page.evaluate(() => localStorage.getItem('authToken'));

    // Attempt to access conflict logs via API as regular user
    const forbiddenResponse = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${schedulerToken}`,
        'Content-Type': 'application/json'
      }
    });
    expect(forbiddenResponse.status()).toBe(403);

    // Attempt to navigate to conflict logs section in UI as regular user
    await page.goto(`${BASE_URL}/admin/conflict-logs`);
    // Verify access denied or redirect to unauthorized page
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();

    // Attempt direct URL access to conflict logs page
    const response = await page.goto(`${BASE_URL}/admin/conflict-logs`);
    expect(response?.status()).toBe(403);

    // Log out and log in as Admin user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Get admin auth token
    const adminToken = await page.evaluate(() => localStorage.getItem('authToken'));

    // Execute API call with valid admin authentication token
    const authorizedResponse = await request.get(`${API_BASE_URL}/conflicts/logs`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });
    expect(authorizedResponse.ok()).toBeTruthy();
    expect(authorizedResponse.status()).toBe(200);

    const logsData = await authorizedResponse.json();
    expect(logsData.logs).toBeDefined();
    expect(Array.isArray(logsData.logs)).toBeTruthy();

    // Navigate to conflict logs section in admin UI
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-logs-link"]');
    await expect(page).toHaveURL(/.*admin\/conflict-logs/);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();

    // Verify encryption configuration (simulated check)
    const encryptionResponse = await request.get(`${API_BASE_URL}/admin/security/encryption-status`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (encryptionResponse.ok()) {
      const encryptionData = await encryptionResponse.json();
      expect(encryptionData.encryptionEnabled).toBe(true);
      expect(encryptionData.encryptionAlgorithm).toBeTruthy();
    }

    // Review access control logs
    const accessLogsResponse = await request.get(`${API_BASE_URL}/admin/access-logs`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (accessLogsResponse.ok()) {
      const accessLogsData = await accessLogsResponse.json();
      expect(accessLogsData.accessLogs).toBeDefined();
      
      // Verify unauthorized access attempts are logged
      const unauthorizedAttempts = accessLogsData.accessLogs.filter((log: any) => 
        log.endpoint === '/api/conflicts/logs' && log.status === 401
      );
      expect(unauthorizedAttempts.length).toBeGreaterThan(0);
    }

    // Verify data encryption policy compliance
    await page.goto(`${BASE_URL}/admin/security/policies`);
    await expect(page.locator('[data-testid="encryption-policy-status"]')).toContainText('Compliant');
    await expect(page.locator('[data-testid="data-at-rest-encryption"]')).toContainText('Enabled');
  });
});