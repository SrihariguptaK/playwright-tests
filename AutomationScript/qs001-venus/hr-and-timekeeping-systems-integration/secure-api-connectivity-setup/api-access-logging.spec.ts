import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

test.describe('API Access Logging - Story 15', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  const LOGGING_DASHBOARD_URL = process.env.LOGGING_DASHBOARD_URL || 'https://admin.example.com/logs';
  const VALID_CLIENT_ID = 'test-client-12345';
  const VALID_API_KEY = 'valid-api-key-token-abc123';
  const INVALID_API_KEY = 'invalid-expired-token-xyz789';
  const TEST_ENDPOINT = '/api/v1/test-resource';

  test('Verify logging of successful API access (happy-path)', async ({ page, request }) => {
    // Step 1: Make authorized API request using valid client credentials to a test endpoint
    const requestTimestamp = new Date().toISOString();
    
    const apiResponse = await request.get(`${API_BASE_URL}${TEST_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${VALID_API_KEY}`,
        'X-Client-ID': VALID_CLIENT_ID
      }
    });

    // Expected Result: Access attempt is logged with correct details
    expect(apiResponse.ok()).toBeTruthy();
    expect(apiResponse.status()).toBe(200);

    // Wait for log processing (allowing time for async logging)
    await page.waitForTimeout(2000);

    // Step 2: Query the centralized logging system for the request using client ID and timestamp
    await page.goto(LOGGING_DASHBOARD_URL);
    
    // Login to logging dashboard if needed
    await page.waitForSelector('[data-testid="login-form"]', { timeout: 5000 }).catch(() => {});
    const loginFormVisible = await page.locator('[data-testid="login-form"]').isVisible().catch(() => false);
    
    if (loginFormVisible) {
      await page.fill('[data-testid="username-input"]', 'admin');
      await page.fill('[data-testid="password-input"]', 'admin123');
      await page.click('[data-testid="login-button"]');
      await page.waitForLoadState('networkidle');
    }

    // Navigate to logs search
    await page.click('[data-testid="logs-menu"]');
    await page.waitForSelector('[data-testid="log-search-form"]');

    // Search for the specific API request log
    await page.fill('[data-testid="client-id-filter"]', VALID_CLIENT_ID);
    await page.fill('[data-testid="endpoint-filter"]', TEST_ENDPOINT);
    await page.fill('[data-testid="timestamp-from"]', requestTimestamp.split('T')[0]);
    await page.click('[data-testid="search-logs-button"]');

    // Expected Result: Log entry is found with accurate data
    await page.waitForSelector('[data-testid="log-results-table"]');
    const logEntries = page.locator('[data-testid="log-entry-row"]');
    await expect(logEntries).toHaveCountGreaterThan(0);

    // Step 3: Verify log entry contains all required fields: timestamp, client ID, endpoint, and result status
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-client-id"]')).toContainText(VALID_CLIENT_ID);
    await expect(firstLogEntry.locator('[data-testid="log-endpoint"]')).toContainText(TEST_ENDPOINT);
    await expect(firstLogEntry.locator('[data-testid="log-result-status"]')).toContainText('200');
    await expect(firstLogEntry.locator('[data-testid="log-result-status"]')).toContainText('SUCCESS');

    // Step 4: Verify the logging operation completed within performance requirements
    const logTimestamp = await firstLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    const logProcessingTime = await firstLogEntry.locator('[data-testid="log-processing-time"]').textContent();
    
    // Verify logging was under 10ms per request
    if (logProcessingTime) {
      const processingTimeMs = parseFloat(logProcessingTime.replace('ms', ''));
      expect(processingTimeMs).toBeLessThan(10);
    }

    // Verify log completeness
    await expect(firstLogEntry.locator('[data-testid="log-complete-indicator"]')).toHaveAttribute('data-complete', 'true');
  });

  test('Verify logging of failed API access (error-case)', async ({ page, request }) => {
    // Step 1: Make unauthorized API request using invalid or expired client credentials
    const requestTimestamp = new Date().toISOString();
    
    const apiResponse = await request.get(`${API_BASE_URL}${TEST_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${INVALID_API_KEY}`,
        'X-Client-ID': VALID_CLIENT_ID
      },
      failOnStatusCode: false
    });

    // Expected Result: Access attempt is logged with failure status
    expect(apiResponse.status()).toBe(401);

    // Wait for log processing and alert generation
    await page.waitForTimeout(3000);

    // Step 2: Query the centralized logging system for the failed request attempt
    await page.goto(LOGGING_DASHBOARD_URL);
    
    // Login to logging dashboard if needed
    await page.waitForSelector('[data-testid="login-form"]', { timeout: 5000 }).catch(() => {});
    const loginFormVisible = await page.locator('[data-testid="login-form"]').isVisible().catch(() => false);
    
    if (loginFormVisible) {
      await page.fill('[data-testid="username-input"]', 'admin');
      await page.fill('[data-testid="password-input"]', 'admin123');
      await page.click('[data-testid="login-button"]');
      await page.waitForLoadState('networkidle');
    }

    // Navigate to logs search
    await page.click('[data-testid="logs-menu"]');
    await page.waitForSelector('[data-testid="log-search-form"]');

    // Filter for failed access attempts
    await page.fill('[data-testid="client-id-filter"]', VALID_CLIENT_ID);
    await page.fill('[data-testid="endpoint-filter"]', TEST_ENDPOINT);
    await page.selectOption('[data-testid="status-filter"]', 'FAILED');
    await page.fill('[data-testid="timestamp-from"]', requestTimestamp.split('T')[0]);
    await page.click('[data-testid="search-logs-button"]');

    // Expected Result: Failed attempt log is found
    await page.waitForSelector('[data-testid="log-results-table"]');
    const logEntries = page.locator('[data-testid="log-entry-row"]');
    await expect(logEntries).toHaveCountGreaterThan(0);

    const failedLogEntry = logEntries.first();
    await expect(failedLogEntry.locator('[data-testid="log-result-status"]')).toContainText('401');
    await expect(failedLogEntry.locator('[data-testid="log-result-status"]')).toContainText('UNAUTHORIZED');

    // Verify the failed attempt log contains complete information for security analysis
    await expect(failedLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(failedLogEntry.locator('[data-testid="log-client-id"]')).toContainText(VALID_CLIENT_ID);
    await expect(failedLogEntry.locator('[data-testid="log-endpoint"]')).toContainText(TEST_ENDPOINT);
    await expect(failedLogEntry.locator('[data-testid="log-failure-reason"]')).toBeVisible();
    await expect(failedLogEntry.locator('[data-testid="log-failure-reason"]')).toContainText(/invalid|expired|unauthorized/i);

    // Step 3: Check alert system for suspicious activity notification related to the failed access attempt
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-dashboard"]');

    // Filter alerts for security-related notifications
    await page.selectOption('[data-testid="alert-type-filter"]', 'SECURITY');
    await page.fill('[data-testid="alert-search-input"]', VALID_CLIENT_ID);
    await page.click('[data-testid="search-alerts-button"]');

    // Expected Result: Alert is generated for failed access attempt
    await page.waitForSelector('[data-testid="alert-list"]');
    const alerts = page.locator('[data-testid="alert-item"]');
    await expect(alerts).toHaveCountGreaterThan(0);

    const securityAlert = alerts.first();
    await expect(securityAlert.locator('[data-testid="alert-title"]')).toContainText(/unauthorized|suspicious|failed access/i);
    await expect(securityAlert.locator('[data-testid="alert-client-id"]')).toContainText(VALID_CLIENT_ID);
    await expect(securityAlert.locator('[data-testid="alert-severity"]')).toContainText(/high|medium/i);
    await expect(securityAlert.locator('[data-testid="alert-status"]')).toContainText(/new|pending review/i);

    // Verify alert contains reference to the failed log entry
    await securityAlert.click();
    await page.waitForSelector('[data-testid="alert-details"]');
    await expect(page.locator('[data-testid="alert-log-reference"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-endpoint"]')).toContainText(TEST_ENDPOINT);
  });
});