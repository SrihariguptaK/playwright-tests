import { test, expect } from '@playwright/test';

test.describe('Story-21: Conflict Logging for Audit and Reporting', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Verify logging of detected conflicts (happy-path)', async ({ page }) => {
    // Navigate to the event creation interface
    await page.goto(`${BASE_URL}/events/create`);
    await expect(page.locator('[data-testid="event-creation-form"]')).toBeVisible();

    // Create a base event: Title='Project Review', Start Time='2:00 PM', End Time='3:00 PM', Date='Tomorrow'
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];

    await page.fill('[data-testid="event-title-input"]', 'Project Review');
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-start-time-input"]', '14:00');
    await page.fill('[data-testid="event-end-time-input"]', '15:00');
    await page.click('[data-testid="create-event-button"]');

    // Verify base event was created successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Event created successfully');

    // Create a conflicting event: Title='Client Meeting', Start Time='2:30 PM', End Time='3:30 PM', Date='Tomorrow'
    await page.goto(`${BASE_URL}/events/create`);
    await page.fill('[data-testid="event-title-input"]', 'Client Meeting');
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-start-time-input"]', '14:30');
    await page.fill('[data-testid="event-end-time-input"]', '15:30');

    // Note the timestamp when the conflict was detected
    const conflictDetectionTime = new Date();
    await page.click('[data-testid="create-event-button"]');

    // Verify conflict was detected
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('Conflict detected');

    // Navigate to the conflict logs interface
    await page.goto(`${BASE_URL}/conflict-logs`);
    await expect(page.locator('[data-testid="conflict-logs-page"]')).toBeVisible();

    // Retrieve conflict logs for the current date/time period
    await page.fill('[data-testid="log-date-filter"]', tomorrowFormatted);
    await page.click('[data-testid="apply-filter-button"]');

    // Wait for logs to load
    await page.waitForSelector('[data-testid="conflict-log-entry"]', { timeout: 5000 });

    // Search for the log entry corresponding to the triggered conflict
    const logEntries = page.locator('[data-testid="conflict-log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(0);

    // Find the specific log entry for our conflict
    let foundConflictLog = false;
    for (let i = 0; i < logCount; i++) {
      const logEntry = logEntries.nth(i);
      const logText = await logEntry.textContent();
      
      if (logText?.includes('Project Review') && logText?.includes('Client Meeting')) {
        foundConflictLog = true;
        
        // Verify log entry contains complete metadata
        await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
        await expect(logEntry.locator('[data-testid="log-involved-resources"]')).toContainText('Project Review');
        await expect(logEntry.locator('[data-testid="log-involved-resources"]')).toContainText('Client Meeting');
        await expect(logEntry.locator('[data-testid="log-conflict-type"]')).toBeVisible();
        await expect(logEntry.locator('[data-testid="log-user"]')).toBeVisible();
        await expect(logEntry.locator('[data-testid="log-event-details"]')).toContainText('14:00');
        await expect(logEntry.locator('[data-testid="log-event-details"]')).toContainText('15:00');
        await expect(logEntry.locator('[data-testid="log-resolution-status"]')).toBeVisible();
        
        // Verify timestamp is within acceptable range (within 1 second of detection)
        const logTimestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
        expect(logTimestamp).toBeTruthy();
        
        break;
      }
    }

    expect(foundConflictLog).toBeTruthy();

    // Alternative: Verify via API endpoint
    const response = await page.request.get(`${API_URL}/conflict-logs`, {
      params: {
        date: tomorrowFormatted
      }
    });
    expect(response.ok()).toBeTruthy();
    const logsData = await response.json();
    expect(logsData.logs).toBeDefined();
    expect(logsData.logs.length).toBeGreaterThan(0);
    
    // Verify log entry exists with accurate metadata
    const apiLogEntry = logsData.logs.find((log: any) => 
      log.involvedResources?.includes('Project Review') && 
      log.involvedResources?.includes('Client Meeting')
    );
    expect(apiLogEntry).toBeDefined();
    expect(apiLogEntry.timestamp).toBeDefined();
    expect(apiLogEntry.conflictType).toBeDefined();
    expect(apiLogEntry.eventDetails).toBeDefined();
  });

  test('Validate secure access to conflict logs (error-case)', async ({ page, context }) => {
    // Log into the system using credentials of an unauthorized user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'unauthorized_user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for login to complete
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Attempt to navigate to the conflict logs interface
    await page.goto(`${BASE_URL}/conflict-logs`);
    
    // Verify access is denied in UI
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Verify conflict logs interface is not accessible
    await expect(page.locator('[data-testid="conflict-logs-page"]')).not.toBeVisible();

    // Attempt to directly access the GET /conflict-logs API endpoint
    const unauthorizedResponse = await page.request.get(`${API_URL}/conflict-logs`);
    
    // Verify API returns 403 Forbidden or 401 Unauthorized
    expect([401, 403]).toContain(unauthorizedResponse.status());
    
    // Verify that no conflict log data is displayed or accessible
    const unauthorizedData = await unauthorizedResponse.json().catch(() => null);
    if (unauthorizedData) {
      expect(unauthorizedData.logs).toBeUndefined();
    }

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log into the system using credentials of an authorized user
    await page.fill('[data-testid="username-input"]', 'authorized_scheduler');
    await page.fill('[data-testid="password-input"]', 'securepass456');
    await page.click('[data-testid="login-button"]');
    
    // Wait for login to complete
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Navigate to the conflict logs interface
    await page.goto(`${BASE_URL}/conflict-logs`);
    
    // Verify authorized access to conflict logs interface
    await expect(page.locator('[data-testid="conflict-logs-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-logs-title"]')).toContainText('Conflict Logs');

    // Verify filtering options are available
    await expect(page.locator('[data-testid="log-date-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-resource-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-conflict-type-filter"]')).toBeVisible();

    // Access the GET /conflict-logs API endpoint with authorized credentials
    const authorizedResponse = await page.request.get(`${API_URL}/conflict-logs`);
    
    // Verify logs are retrieved successfully
    expect(authorizedResponse.ok()).toBeTruthy();
    expect(authorizedResponse.status()).toBe(200);
    
    const authorizedData = await authorizedResponse.json();
    expect(authorizedData.logs).toBeDefined();
    expect(Array.isArray(authorizedData.logs)).toBeTruthy();

    // Verify conflict log entries are displayed with complete information
    const logEntries = page.locator('[data-testid="conflict-log-entry"]');
    const logCount = await logEntries.count();
    
    if (logCount > 0) {
      const firstLogEntry = logEntries.first();
      await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
      await expect(firstLogEntry.locator('[data-testid="log-involved-resources"]')).toBeVisible();
      await expect(firstLogEntry.locator('[data-testid="log-conflict-type"]')).toBeVisible();
    }

    // Test filtering by date
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="log-date-filter"]', today);
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();

    // Test filtering by resource
    await page.fill('[data-testid="log-resource-filter"]', 'Project Review');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();

    // Test filtering by conflict type
    await page.selectOption('[data-testid="log-conflict-type-filter"]', 'time-overlap');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="conflict-logs-table"]')).toBeVisible();
  });
});