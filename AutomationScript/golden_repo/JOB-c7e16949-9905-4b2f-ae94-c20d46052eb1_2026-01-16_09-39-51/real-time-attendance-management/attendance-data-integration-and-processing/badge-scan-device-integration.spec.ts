import { test, expect } from '@playwright/test';

test.describe('Badge Scan Device Integration - Story 2', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_ENDPOINT = '/api/attendance/ingest-badge';
  const VALID_DEVICE_URL = 'https://badge-device-api.example.com';
  const VALID_CLIENT_ID = 'test-client-id-12345';
  const VALID_CLIENT_SECRET = 'test-client-secret-67890';
  const VALID_EMPLOYEE_ID = 'EMP-001';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/attendance/devices`);
  });

  test('Validate successful connection and data ingestion from badge scan device', async ({ page, request }) => {
    // Step 1: Navigate to the badge scan device configuration page
    await expect(page).toHaveURL(/.*devices/);
    await expect(page.locator('[data-testid="device-config-page"]')).toBeVisible();

    // Step 2: Enter valid badge scan device API endpoint URL
    await page.locator('[data-testid="device-api-endpoint"]').fill(VALID_DEVICE_URL);
    await expect(page.locator('[data-testid="device-api-endpoint"]')).toHaveValue(VALID_DEVICE_URL);

    // Step 3: Enter valid OAuth2 credentials
    await page.locator('[data-testid="oauth-client-id"]').fill(VALID_CLIENT_ID);
    await page.locator('[data-testid="oauth-client-secret"]').fill(VALID_CLIENT_SECRET);
    await expect(page.locator('[data-testid="oauth-client-id"]')).toHaveValue(VALID_CLIENT_ID);

    // Step 4: Click 'Test Connection' button
    await page.locator('[data-testid="test-connection-btn"]').click();
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connection successful', { timeout: 10000 });

    // Step 5: Save the badge scan device configuration
    await page.locator('[data-testid="save-config-btn"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Configuration saved successfully');

    // Step 6: Simulate a badge scan event
    const scanTimestamp = new Date().toISOString();
    const badgeScanEvent = {
      employeeId: VALID_EMPLOYEE_ID,
      scanTimestamp: scanTimestamp,
      deviceId: 'BADGE-DEVICE-001',
      location: 'Main Entrance'
    };

    const startTime = Date.now();
    const response = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: badgeScanEvent,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Step 7: Verify system receives and processes event within 1 minute
    const processingTime = Date.now() - startTime;
    expect(response.ok()).toBeTruthy();
    expect(processingTime).toBeLessThan(60000);

    // Step 8: Verify attendance record appears in database
    await page.goto(`${BASE_URL}/admin/attendance/records`);
    await page.locator('[data-testid="search-employee-id"]').fill(VALID_EMPLOYEE_ID);
    await page.locator('[data-testid="search-btn"]').click();
    await expect(page.locator(`[data-testid="attendance-record-${VALID_EMPLOYEE_ID}"]`)).toBeVisible();

    // Step 9: Navigate to ingestion logs dashboard
    await page.goto(`${BASE_URL}/admin/attendance/ingestion-logs`);
    await expect(page.locator('[data-testid="ingestion-logs-dashboard"]')).toBeVisible();

    // Step 10: Search for the simulated badge scan event in logs
    await page.locator('[data-testid="log-search-input"]').fill(VALID_EMPLOYEE_ID);
    await page.locator('[data-testid="log-search-btn"]').click();
    
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toContainText('success');
    await expect(logEntry).toContainText(VALID_EMPLOYEE_ID);
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
  });

  test('Verify rejection of invalid badge scan events', async ({ page, request }) => {
    // Step 1: Prepare badge scan event with missing employee ID
    const invalidEventMissingId = {
      scanTimestamp: new Date().toISOString(),
      deviceId: 'BADGE-DEVICE-001',
      location: 'Main Entrance'
    };

    // Step 2: Send event with missing employee ID
    const response1 = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: invalidEventMissingId,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Step 3: Verify API response status code and error message
    expect(response1.status()).toBe(400);
    const responseBody1 = await response1.json();
    expect(responseBody1.error).toContain('employee ID');

    // Step 4: Check no attendance record was created
    await page.goto(`${BASE_URL}/admin/attendance/records`);
    await page.locator('[data-testid="search-employee-id"]').fill('undefined');
    await page.locator('[data-testid="search-btn"]').click();
    await expect(page.locator('[data-testid="no-records-message"]')).toBeVisible();

    // Step 5: Navigate to error logs dashboard
    await page.goto(`${BASE_URL}/admin/attendance/error-logs`);
    await expect(page.locator('[data-testid="error-logs-dashboard"]')).toBeVisible();

    // Step 6: Search for rejected event in error logs
    await page.locator('[data-testid="error-log-filter"]').selectOption('validation-error');
    const errorLog1 = page.locator('[data-testid="error-log-entry"]').first();
    await expect(errorLog1).toContainText('missing employee ID');
    await expect(errorLog1).toContainText('validation error');

    // Step 7: Prepare second event with invalid timestamp format
    const invalidEventBadTimestamp = {
      employeeId: 'EMP-002',
      scanTimestamp: 'not-a-valid-timestamp',
      deviceId: 'BADGE-DEVICE-001',
      location: 'Main Entrance'
    };

    // Step 8: Send event with invalid timestamp
    const response2 = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: invalidEventBadTimestamp,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Step 9: Verify API response status code and error message
    expect(response2.status()).toBe(400);
    const responseBody2 = await response2.json();
    expect(responseBody2.error).toContain('timestamp');

    // Step 10: Check no attendance record was created for this event
    await page.goto(`${BASE_URL}/admin/attendance/records`);
    await page.locator('[data-testid="search-employee-id"]').fill('EMP-002');
    await page.locator('[data-testid="search-btn"]').click();
    await expect(page.locator('[data-testid="no-records-message"]')).toBeVisible();

    // Step 11: Review error logs dashboard for all rejected events
    await page.goto(`${BASE_URL}/admin/attendance/error-logs`);
    await page.locator('[data-testid="refresh-logs-btn"]').click();
    
    const errorLogEntries = page.locator('[data-testid="error-log-entry"]');
    await expect(errorLogEntries).toHaveCount(2, { timeout: 5000 });
    
    await expect(errorLogEntries.nth(0)).toContainText('validation error');
    await expect(errorLogEntries.nth(1)).toContainText('validation error');
    
    const errorLog2 = errorLogEntries.filter({ hasText: 'invalid timestamp' });
    await expect(errorLog2).toHaveCount(1);
    await expect(errorLog2.first()).toContainText('EMP-002');
  });

  test('Test automatic retry on badge scan ingestion failure', async ({ page, request, context }) => {
    // Step 1: Prepare valid badge scan event
    const validBadgeScanEvent = {
      employeeId: 'EMP-003',
      scanTimestamp: new Date().toISOString(),
      deviceId: 'BADGE-DEVICE-001',
      location: 'Main Entrance'
    };

    // Step 2: Configure network simulation to block connectivity
    await context.route(`${BASE_URL}${API_ENDPOINT}`, route => {
      if (route.request().method() === 'POST') {
        route.abort('failed');
      } else {
        route.continue();
      }
    });

    // Step 3: Send valid badge scan event (will fail due to network block)
    await page.goto(`${BASE_URL}/admin/attendance/ingestion-logs`);
    
    // Trigger ingestion through UI or API
    const failedAttempt = request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: validBadgeScanEvent,
      headers: {
        'Content-Type': 'application/json'
      }
    }).catch(error => {
      expect(error).toBeDefined();
    });

    // Step 4: Monitor system logs for automatic retry attempts
    await page.goto(`${BASE_URL}/admin/attendance/retry-logs`);
    await page.waitForTimeout(2000);
    
    // Step 5: Verify first retry attempt fails
    await page.locator('[data-testid="refresh-retry-logs-btn"]').click();
    const retryLog1 = page.locator('[data-testid="retry-log-entry"]').filter({ hasText: 'Retry attempt 1' });
    await expect(retryLog1).toBeVisible({ timeout: 10000 });
    await expect(retryLog1).toContainText('failed');

    // Step 6: Monitor for second automatic retry attempt
    await page.waitForTimeout(3000);
    await page.locator('[data-testid="refresh-retry-logs-btn"]').click();
    
    // Step 7: Verify second retry attempt fails
    const retryLog2 = page.locator('[data-testid="retry-log-entry"]').filter({ hasText: 'Retry attempt 2' });
    await expect(retryLog2).toBeVisible({ timeout: 10000 });
    await expect(retryLog2).toContainText('failed');

    // Step 8: Monitor for third automatic retry attempt and restore network
    await page.waitForTimeout(3000);
    
    // Step 9: Restore network connectivity before third retry completes
    await context.unroute(`${BASE_URL}${API_ENDPOINT}`);
    
    await page.waitForTimeout(2000);
    await page.locator('[data-testid="refresh-retry-logs-btn"]').click();

    // Step 10: Verify third retry attempt succeeds
    const retryLog3 = page.locator('[data-testid="retry-log-entry"]').filter({ hasText: 'Retry attempt 3' });
    await expect(retryLog3).toBeVisible({ timeout: 10000 });
    await expect(retryLog3).toContainText('success');

    // Step 11: Check attendance database for badge scan event record
    await page.goto(`${BASE_URL}/admin/attendance/records`);
    await page.locator('[data-testid="search-employee-id"]').fill('EMP-003');
    await page.locator('[data-testid="search-btn"]').click();
    await expect(page.locator(`[data-testid="attendance-record-EMP-003"]`)).toBeVisible();

    // Step 12: Review ingestion logs for complete retry history
    await page.goto(`${BASE_URL}/admin/attendance/ingestion-logs`);
    await page.locator('[data-testid="log-search-input"]').fill('EMP-003');
    await page.locator('[data-testid="log-search-btn"]').click();
    
    const ingestionLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'EMP-003' });
    await expect(ingestionLog).toBeVisible();
    await expect(ingestionLog).toContainText('success');
    await expect(ingestionLog.locator('[data-testid="retry-count"]')).toContainText('3');

    // Step 13: Check alert notifications dashboard
    await page.goto(`${BASE_URL}/admin/alerts`);
    await expect(page.locator('[data-testid="alerts-dashboard"]')).toBeVisible();
    
    // Step 14: Verify no alert sent since ingestion succeeded after retries
    const alertsForEmployee = page.locator('[data-testid="alert-item"]').filter({ hasText: 'EMP-003' });
    await expect(alertsForEmployee).toHaveCount(0);

    // Step 15: Verify system continues to process new events normally
    const newEvent = {
      employeeId: 'EMP-004',
      scanTimestamp: new Date().toISOString(),
      deviceId: 'BADGE-DEVICE-001',
      location: 'Main Entrance'
    };

    const newResponse = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: newEvent,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    expect(newResponse.ok()).toBeTruthy();
    
    await page.goto(`${BASE_URL}/admin/attendance/records`);
    await page.locator('[data-testid="search-employee-id"]').fill('EMP-004');
    await page.locator('[data-testid="search-btn"]').click();
    await expect(page.locator(`[data-testid="attendance-record-EMP-004"]`)).toBeVisible();
  });
});