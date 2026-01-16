import { test, expect } from '@playwright/test';
import * as https from 'https';

test.describe('Story-17: Secure Data Transmission Between Quoting Module and Rating Engine', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  const QUOTING_API_ENDPOINT = '/api/v1/quote';
  const RATING_ENGINE_ENDPOINT = '/api/v1/rating';

  test.beforeEach(async ({ page }) => {
    // Navigate to the quoting module application
    await page.goto('/quoting-module');
  });

  test('TC#1: Verify encrypted API communication (happy-path)', async ({ page, request }) => {
    // Step 1: Initiate API request from quoting module
    const apiRequestPromise = page.waitForResponse(
      response => response.url().includes(RATING_ENGINE_ENDPOINT) && response.status() === 200
    );

    // Trigger quote submission that initiates API call to rating engine
    await page.fill('[data-testid="customer-name-input"]', 'John Doe');
    await page.fill('[data-testid="coverage-amount-input"]', '100000');
    await page.click('[data-testid="submit-quote-button"]');

    const apiResponse = await apiRequestPromise;

    // Step 1 Expected Result: Connection established using TLS 1.2+
    const securityDetails = await apiResponse.securityDetails();
    expect(securityDetails).not.toBeNull();
    expect(securityDetails?.protocol()).toMatch(/TLS 1\.[2-3]|TLSv1\.[2-3]/);

    // Step 2: Intercept network traffic
    // Verify the connection uses HTTPS protocol
    const responseUrl = apiResponse.url();
    expect(responseUrl).toMatch(/^https:\/\//);

    // Step 2 Expected Result: Data is encrypted and unreadable
    // Verify that the security details indicate encryption
    expect(securityDetails?.protocol()).toBeTruthy();
    expect(securityDetails?.subjectName()).toBeTruthy();

    // Step 3: Check system logs for encryption status
    await page.goto('/admin/system-logs');
    await page.fill('[data-testid="log-search-input"]', 'encryption');
    await page.click('[data-testid="search-logs-button"]');

    // Step 3 Expected Result: Encryption confirmed in logs
    const encryptionLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: /TLS|encryption|secure/ }).first();
    await expect(encryptionLogEntry).toBeVisible({ timeout: 10000 });
    await expect(encryptionLogEntry).toContainText(/TLS 1\.[2-3]|encrypted|secure connection/);

    // Verify API response confirms successful data transmission
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('success', true);
    expect(responseBody).toHaveProperty('quoteId');
  });

  test('TC#2: Test input sanitization against injection attacks - SQL Injection (error-case)', async ({ page, request }) => {
    // Step 1: Prepare API request with malicious SQL injection payload
    const maliciousSQLPayload = "' OR '1'='1";

    // Navigate to quoting module
    await page.goto('/quoting-module');

    // Step 2: Send API request with malicious SQL injection payload
    const apiRequestPromise = page.waitForResponse(
      response => response.url().includes(RATING_ENGINE_ENDPOINT)
    );

    await page.fill('[data-testid="customer-name-input"]', maliciousSQLPayload);
    await page.fill('[data-testid="coverage-amount-input"]', maliciousSQLPayload);
    await page.click('[data-testid="submit-quote-button"]');

    const apiResponse = await apiRequestPromise;

    // Step 2 Expected Result: System rejects input and logs security event
    expect(apiResponse.status()).toBe(400);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/invalid input|sanitization|rejected/);

    // Step 3: Access security event logs
    await page.goto('/admin/security-logs');
    await page.fill('[data-testid="log-search-input"]', 'injection');
    await page.selectOption('[data-testid="log-type-filter"]', 'security');
    await page.click('[data-testid="search-logs-button"]');

    // Step 3 Expected Result: Security event logged for rejected request
    const securityLogEntry = page.locator('[data-testid="security-log-entry"]').filter({ hasText: /injection|malicious|rejected/ }).first();
    await expect(securityLogEntry).toBeVisible({ timeout: 10000 });
    await expect(securityLogEntry).toContainText(/SQL injection|input rejected|security event/);

    // Step 5: Verify no unauthorized data access occurs
    await page.goto('/admin/database-integrity');
    await page.click('[data-testid="check-integrity-button"]');

    // Step 5 Expected Result: System remains secure with no breaches
    const integrityStatus = page.locator('[data-testid="integrity-status"]');
    await expect(integrityStatus).toContainText(/intact|secure|no breaches/);
    await expect(integrityStatus).not.toContainText(/compromised|breach|unauthorized/);
  });

  test('TC#3: Test input sanitization against XSS attacks (error-case)', async ({ page }) => {
    // Step 4: Prepare and send API request with XSS payload
    const maliciousXSSPayload = "<script>alert('XSS')</script>";

    await page.goto('/quoting-module');

    const apiRequestPromise = page.waitForResponse(
      response => response.url().includes(RATING_ENGINE_ENDPOINT)
    );

    await page.fill('[data-testid="customer-name-input"]', maliciousXSSPayload);
    await page.fill('[data-testid="notes-input"]', maliciousXSSPayload);
    await page.click('[data-testid="submit-quote-button"]');

    const apiResponse = await apiRequestPromise;

    // Expected Result: System rejects XSS input
    expect(apiResponse.status()).toBe(400);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/invalid input|sanitization|rejected/);

    // Verify security event is logged
    await page.goto('/admin/security-logs');
    await page.fill('[data-testid="log-search-input"]', 'XSS');
    await page.click('[data-testid="search-logs-button"]');

    const xssLogEntry = page.locator('[data-testid="security-log-entry"]').filter({ hasText: /XSS|script|malicious/ }).first();
    await expect(xssLogEntry).toBeVisible({ timeout: 10000 });

    // Step 5: Verify database and system integrity
    await page.goto('/admin/system-monitoring');
    await page.click('[data-testid="refresh-monitoring-button"]');

    // Step 6: Confirm no data breach indicators
    const breachIndicators = page.locator('[data-testid="breach-indicator"]');
    await expect(breachIndicators).toHaveCount(0);

    const systemStatus = page.locator('[data-testid="system-status"]');
    await expect(systemStatus).toContainText(/secure|normal|no threats/);
  });

  test('TC#4: Verify OAuth 2.0 authentication token validation', async ({ page, request }) => {
    // Test with invalid/missing authentication token
    const response = await request.post(`${API_BASE_URL}${RATING_ENGINE_ENDPOINT}`, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid_token_12345'
      },
      data: {
        customerName: 'Test Customer',
        coverageAmount: 50000
      }
    });

    // Expected Result: Request rejected due to invalid token
    expect(response.status()).toBe(401);
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|invalid token|authentication failed/);

    // Verify authentication failure is logged
    await page.goto('/admin/security-logs');
    await page.fill('[data-testid="log-search-input"]', 'authentication failure');
    await page.click('[data-testid="search-logs-button"]');

    const authFailureLog = page.locator('[data-testid="security-log-entry"]').filter({ hasText: /authentication failure|invalid token/ }).first();
    await expect(authFailureLog).toBeVisible({ timeout: 10000 });
  });

  test('TC#5: Verify all API traffic is encrypted', async ({ page }) => {
    // Monitor multiple API calls to ensure all use encryption
    const apiCalls: any[] = [];

    page.on('response', async (response) => {
      if (response.url().includes('/api/')) {
        apiCalls.push({
          url: response.url(),
          status: response.status(),
          securityDetails: await response.securityDetails()
        });
      }
    });

    await page.goto('/quoting-module');
    await page.fill('[data-testid="customer-name-input"]', 'Jane Smith');
    await page.fill('[data-testid="coverage-amount-input"]', '75000');
    await page.click('[data-testid="submit-quote-button"]');

    await page.waitForTimeout(2000);

    // Verify all API calls use HTTPS and TLS 1.2+
    expect(apiCalls.length).toBeGreaterThan(0);
    
    for (const call of apiCalls) {
      expect(call.url).toMatch(/^https:\/\//);
      if (call.securityDetails) {
        expect(call.securityDetails.protocol()).toMatch(/TLS 1\.[2-3]|TLSv1\.[2-3]/);
      }
    }
  });
});