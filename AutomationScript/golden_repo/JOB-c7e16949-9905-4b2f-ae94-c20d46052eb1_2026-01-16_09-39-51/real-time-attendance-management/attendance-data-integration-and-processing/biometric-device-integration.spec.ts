import { test, expect } from '@playwright/test';

test.describe('Biometric Device Integration - Attendance Data Ingestion', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_ENDPOINT = '/api/attendance/ingest';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/biometric-devices`);
  });

  test('Validate successful connection and data ingestion from biometric device', async ({ page, request }) => {
    // Step 1: Navigate to the biometric device configuration page
    await expect(page.locator('[data-testid="biometric-config-page"]')).toBeVisible();
    
    // Step 2: Enter valid biometric device API endpoint URL
    await page.fill('[data-testid="device-api-endpoint"]', 'https://biometric-device.example.com/api');
    
    // Step 3: Enter valid OAuth2 credentials
    await page.fill('[data-testid="oauth-client-id"]', 'test-client-id-12345');
    await page.fill('[data-testid="oauth-client-secret"]', 'test-client-secret-67890');
    
    // Step 4: Click 'Test Connection' button to initiate authentication
    await page.click('[data-testid="test-connection-btn"]');
    
    // Expected Result: System establishes authenticated connection successfully
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected', { timeout: 10000 });
    await expect(page.locator('[data-testid="auth-status"]')).toContainText('Authenticated');
    
    // Step 5: Save the biometric device configuration settings
    await page.click('[data-testid="save-config-btn"]');
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Configuration saved successfully');
    
    // Step 6: Simulate an attendance event from the biometric device
    const eventTimestamp = new Date().toISOString();
    const attendanceEvent = {
      employeeId: 'EMP-001',
      timestamp: eventTimestamp,
      deviceId: 'BIO-DEVICE-001',
      eventType: 'check-in'
    };
    
    const startTime = Date.now();
    const response = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: attendanceEvent,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    const processingTime = Date.now() - startTime;
    
    // Expected Result: System receives and processes event within 1 minute
    expect(response.status()).toBe(200);
    expect(processingTime).toBeLessThan(60000);
    
    // Step 7: Verify the attendance record appears in the system database
    await page.goto(`${BASE_URL}/admin/attendance-records`);
    await page.fill('[data-testid="search-employee-id"]', 'EMP-001');
    await page.click('[data-testid="search-btn"]');
    await expect(page.locator('[data-testid="attendance-record-row"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="employee-id"]').first()).toContainText('EMP-001');
    
    // Step 8: Navigate to the ingestion logs dashboard
    await page.goto(`${BASE_URL}/admin/ingestion-logs`);
    
    // Step 9: Search for the simulated attendance event in the ingestion logs
    await page.fill('[data-testid="log-search-employee-id"]', 'EMP-001');
    await page.click('[data-testid="log-search-btn"]');
    
    // Expected Result: Event logged with success status and timestamp
    await expect(page.locator('[data-testid="log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="log-status"]').first()).toContainText('success');
    await expect(page.locator('[data-testid="log-timestamp"]').first()).toBeVisible();
  });

  test('Verify rejection of invalid attendance events', async ({ page, request }) => {
    // Step 1: Prepare an attendance event payload with missing employee ID field
    const invalidEvent1 = {
      timestamp: new Date().toISOString(),
      deviceId: 'BIO-DEVICE-001',
      eventType: 'check-in'
    };
    
    // Step 2: Send the attendance event with missing employee ID
    const response1 = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: invalidEvent1,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: System rejects event and logs validation error
    expect(response1.status()).toBe(400);
    const responseBody1 = await response1.json();
    expect(responseBody1.error).toContain('employee');
    
    // Step 3: Check that no attendance record was created in the database
    await page.goto(`${BASE_URL}/admin/attendance-records`);
    await page.fill('[data-testid="search-device-id"]', 'BIO-DEVICE-001');
    await page.click('[data-testid="search-btn"]');
    const noRecordsMessage = page.locator('[data-testid="no-records-message"]');
    await expect(noRecordsMessage).toBeVisible();
    
    // Step 4: Navigate to the error logs dashboard
    await page.goto(`${BASE_URL}/admin/error-logs`);
    
    // Step 5: Search for the rejected event in error logs
    await page.fill('[data-testid="error-log-search"]', 'missing employee ID');
    await page.click('[data-testid="error-log-search-btn"]');
    
    // Expected Result: All invalid events are recorded with detailed error messages
    await expect(page.locator('[data-testid="error-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]').first()).toContainText('employee');
    
    // Step 6: Prepare a second attendance event with invalid timestamp format
    const invalidEvent2 = {
      employeeId: 'EMP-002',
      timestamp: 'invalid-date-format',
      deviceId: 'BIO-DEVICE-001',
      eventType: 'check-in'
    };
    
    // Step 7: Send the attendance event with invalid timestamp format
    const response2 = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: invalidEvent2,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    // Expected Result: System rejects event and logs validation error
    expect(response2.status()).toBe(400);
    const responseBody2 = await response2.json();
    expect(responseBody2.error).toContain('timestamp');
    
    // Step 8: Check that no attendance record was created for this event
    await page.goto(`${BASE_URL}/admin/attendance-records`);
    await page.fill('[data-testid="search-employee-id"]', 'EMP-002');
    await page.click('[data-testid="search-btn"]');
    await expect(page.locator('[data-testid="no-records-message"]')).toBeVisible();
    
    // Step 9: Review the error logs dashboard for all rejected events
    await page.goto(`${BASE_URL}/admin/error-logs`);
    await page.fill('[data-testid="error-log-search"]', 'invalid timestamp');
    await page.click('[data-testid="error-log-search-btn"]');
    await expect(page.locator('[data-testid="error-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]').first()).toContainText('timestamp');
  });

  test('Test automatic retry on ingestion failure', async ({ page, request, context }) => {
    // Step 1: Prepare a valid attendance event
    const validEvent = {
      employeeId: 'EMP-003',
      timestamp: new Date().toISOString(),
      deviceId: 'BIO-DEVICE-002',
      eventType: 'check-in'
    };
    
    // Step 2: Configure network simulation to block connectivity
    await context.route(`${BASE_URL}${API_ENDPOINT}`, route => {
      const requestCount = (route.request() as any).retryCount || 0;
      
      // Fail first two attempts, succeed on third
      if (requestCount < 2) {
        route.abort('failed');
      } else {
        route.continue();
      }
    });
    
    // Step 3: Send the valid attendance event
    let retryCount = 0;
    const maxRetries = 3;
    let lastResponse;
    
    // Step 4-8: Monitor retry attempts and verify behavior
    for (let i = 0; i < maxRetries; i++) {
      try {
        lastResponse = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
          data: validEvent,
          headers: {
            'Content-Type': 'application/json'
          },
          timeout: 5000
        });
        
        if (lastResponse.status() === 200) {
          retryCount = i + 1;
          break;
        }
      } catch (error) {
        retryCount = i + 1;
        // Expected Result: First and second retry attempts fail
        if (i < 2) {
          expect(error).toBeDefined();
        }
        
        // Wait before retry
        await page.waitForTimeout(1000);
      }
    }
    
    // Expected Result: Third retry attempt succeeds
    expect(retryCount).toBeLessThanOrEqual(3);
    
    // Step 9: Check the attendance database for the event record
    await page.goto(`${BASE_URL}/admin/attendance-records`);
    await page.fill('[data-testid="search-employee-id"]', 'EMP-003');
    await page.click('[data-testid="search-btn"]');
    await expect(page.locator('[data-testid="attendance-record-row"]').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="employee-id"]').first()).toContainText('EMP-003');
    
    // Step 10: Review the ingestion logs for complete retry history
    await page.goto(`${BASE_URL}/admin/ingestion-logs`);
    await page.fill('[data-testid="log-search-employee-id"]', 'EMP-003');
    await page.click('[data-testid="log-search-btn"]');
    await expect(page.locator('[data-testid="log-entry"]')).toHaveCount(retryCount);
    await expect(page.locator('[data-testid="log-status"]').last()).toContainText('success');
    
    // Step 11: Check the alert notifications dashboard
    await page.goto(`${BASE_URL}/admin/alerts`);
    await page.fill('[data-testid="alert-search"]', 'EMP-003');
    await page.click('[data-testid="alert-search-btn"]');
    
    // Expected Result: No alert sent if ingestion succeeds after retries
    const noAlertsMessage = page.locator('[data-testid="no-alerts-message"]');
    await expect(noAlertsMessage).toBeVisible();
    
    // Step 12: Verify system continues to process new events normally
    const newEvent = {
      employeeId: 'EMP-004',
      timestamp: new Date().toISOString(),
      deviceId: 'BIO-DEVICE-002',
      eventType: 'check-out'
    };
    
    const newResponse = await request.post(`${BASE_URL}${API_ENDPOINT}`, {
      data: newEvent,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    expect(newResponse.status()).toBe(200);
  });
});