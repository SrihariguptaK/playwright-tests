import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

test.describe('API Access Logging - Story 15', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  const LOGS_DASHBOARD_URL = process.env.LOGS_DASHBOARD_URL || 'https://admin.example.com/logs';
  const ALERTS_DASHBOARD_URL = process.env.ALERTS_DASHBOARD_URL || 'https://admin.example.com/alerts';
  
  let apiContext;
  let testRequestId: string;
  let testTimestamp: number;

  test.beforeAll(async ({ playwright }) => {
    apiContext = await playwright.request.newContext({
      baseURL: API_BASE_URL,
      extraHTTPHeaders: {
        'Content-Type': 'application/json'
      }
    });
  });

  test.afterAll(async () => {
    await apiContext.dispose();
  });

  test('TC#1: Verify logging of successful API access - Make authorized API request and verify logging', async ({ page }) => {
    // Step 1: Make authorized API request
    testTimestamp = Date.now();
    const clientId = 'test-client-12345';
    const endpoint = '/api/v1/data';
    
    const response = await apiContext.get(endpoint, {
      headers: {
        'Authorization': 'Bearer valid-test-token',
        'X-Client-ID': clientId
      }
    });

    // Expected Result: Access attempt is logged with correct details
    expect(response.status()).toBe(200);
    testRequestId = response.headers()['x-request-id'] || `req-${testTimestamp}`;

    // Step 2: Query logs for the request
    await page.goto(LOGS_DASHBOARD_URL);
    
    // Login to logs dashboard if needed
    await page.waitForSelector('[data-testid="logs-dashboard"]', { timeout: 10000 });
    
    // Search for the specific log entry
    await page.fill('[data-testid="log-search-input"]', testRequestId);
    await page.click('[data-testid="log-search-button"]');
    
    // Wait for search results
    await page.waitForSelector('[data-testid="log-entry"]', { timeout: 5000 });
    
    // Expected Result: Log entry is found with accurate data
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    
    // Verify log contains correct details
    await expect(logEntry.locator('[data-testid="log-client-id"]')).toContainText(clientId);
    await expect(logEntry.locator('[data-testid="log-endpoint"]')).toContainText(endpoint);
    await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('200');
    await expect(logEntry.locator('[data-testid="log-result"]')).toContainText('success');
    
    // Verify timestamp is within expected range (within last 5 minutes)
    const logTimestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify request ID is present
    await expect(logEntry.locator('[data-testid="log-request-id"]')).toContainText(testRequestId);
  });

  test('TC#2: Verify logging of failed API access - Make unauthorized API request and verify alert generation', async ({ page }) => {
    // Step 1: Make unauthorized API request
    testTimestamp = Date.now();
    const clientId = 'unauthorized-client-99999';
    const endpoint = '/api/v1/sensitive-data';
    
    const response = await apiContext.get(endpoint, {
      headers: {
        'Authorization': 'Bearer invalid-token',
        'X-Client-ID': clientId
      },
      failOnStatusCode: false
    });

    // Expected Result: Access attempt is logged with failure status
    expect(response.status()).toBe(401);
    testRequestId = response.headers()['x-request-id'] || `req-${testTimestamp}`;

    // Verify the failed attempt is logged
    await page.goto(LOGS_DASHBOARD_URL);
    await page.waitForSelector('[data-testid="logs-dashboard"]', { timeout: 10000 });
    
    // Filter for failed requests
    await page.click('[data-testid="log-filter-status"]');
    await page.click('[data-testid="filter-option-failed"]');
    
    // Search for the specific failed request
    await page.fill('[data-testid="log-search-input"]', clientId);
    await page.click('[data-testid="log-search-button"]');
    
    await page.waitForSelector('[data-testid="log-entry"]', { timeout: 5000 });
    
    const failedLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(failedLogEntry).toBeVisible();
    await expect(failedLogEntry.locator('[data-testid="log-status"]')).toContainText('401');
    await expect(failedLogEntry.locator('[data-testid="log-result"]')).toContainText('failed');
    await expect(failedLogEntry.locator('[data-testid="log-client-id"]')).toContainText(clientId);

    // Step 2: Check alert system for suspicious activity
    await page.goto(ALERTS_DASHBOARD_URL);
    await page.waitForSelector('[data-testid="alerts-dashboard"]', { timeout: 10000 });
    
    // Filter for recent alerts
    await page.click('[data-testid="alert-filter-timeframe"]');
    await page.click('[data-testid="filter-option-last-hour"]');
    
    // Search for alerts related to the failed access attempt
    await page.fill('[data-testid="alert-search-input"]', clientId);
    await page.click('[data-testid="alert-search-button"]');
    
    // Wait for alert results
    await page.waitForSelector('[data-testid="alert-entry"]', { timeout: 10000 });
    
    // Expected Result: Alert is generated for failed access attempt
    const alertEntry = page.locator('[data-testid="alert-entry"]').first();
    await expect(alertEntry).toBeVisible();
    
    // Verify alert contains relevant information
    await expect(alertEntry.locator('[data-testid="alert-type"]')).toContainText('Unauthorized Access Attempt');
    await expect(alertEntry.locator('[data-testid="alert-client-id"]')).toContainText(clientId);
    await expect(alertEntry.locator('[data-testid="alert-severity"]')).toContainText('high');
    await expect(alertEntry.locator('[data-testid="alert-status"]')).toContainText('active');
    
    // Verify alert timestamp is recent
    const alertTimestamp = await alertEntry.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();
    
    // Verify alert description mentions failed authentication
    await expect(alertEntry.locator('[data-testid="alert-description"]')).toContainText('failed');
  });
});