import { test, expect } from '@playwright/test';

test.describe('OAuth 2.0 Authentication Configuration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_CLIENT_ID = 'test-client-id-12345';
  const VALID_CLIENT_SECRET = 'test-client-secret-67890';
  const API_ENDPOINT = '/api/protected/employees';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/integration/settings`);
  });

  test('Validate successful OAuth 2.0 token acquisition', async ({ page }) => {
    // Step 1: Navigate to integration settings page
    await expect(page).toHaveURL(/.*integration\/settings/);
    await expect(page.locator('[data-testid="integration-settings-header"]')).toBeVisible();

    // Step 2: Enter valid client ID in the Client ID field
    await page.fill('[data-testid="client-id-input"]', VALID_CLIENT_ID);
    await expect(page.locator('[data-testid="client-id-input"]')).toHaveValue(VALID_CLIENT_ID);

    // Step 3: Enter valid client secret in the Client Secret field
    await page.fill('[data-testid="client-secret-input"]', VALID_CLIENT_SECRET);
    await expect(page.locator('[data-testid="client-secret-input"]')).toHaveValue(VALID_CLIENT_SECRET);

    // Step 4: Click 'Save' or 'Apply' button to store the credentials
    await page.click('[data-testid="save-credentials-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Credentials accepted without errors');

    // Step 5: Initiate OAuth token request
    await page.click('[data-testid="request-token-button"]');
    await page.waitForResponse(response => response.url().includes('/auth/token') && response.status() === 200);

    // Step 6: Verify the OAuth server response for access token
    await expect(page.locator('[data-testid="token-status"]')).toContainText('Access token received');
    await expect(page.locator('[data-testid="token-expiry"]')).toBeVisible();

    // Step 7: Check system logs for token acquisition event
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="logs-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Token acquisition successful');

    // Step 8: Use the acquired access token to call a protected API endpoint
    const apiResponse = await page.request.get(`${BASE_URL}${API_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${await page.locator('[data-testid="access-token-value"]').textContent()}`
      }
    });

    // Step 9: Verify API call succeeds with 200 OK response
    expect(apiResponse.status()).toBe(200);
    expect(apiResponse.headers()['authorization']).toMatch(/^Bearer /);
  });

  test('Verify rejection of API calls with invalid tokens', async ({ page }) => {
    const EXPIRED_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.expired';
    const MALFORMED_TOKEN = 'invalid-malformed-token-xyz';

    // Step 1: Obtain or generate an expired access token
    await page.goto(`${BASE_URL}/integration/testing`);
    await page.fill('[data-testid="test-token-input"]', EXPIRED_TOKEN);

    // Step 2: Send API request with expired access token
    const expiredTokenResponse = await page.request.get(`${BASE_URL}${API_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${EXPIRED_TOKEN}`
      }
    });

    // Step 3: Verify API returns 401 Unauthorized error
    expect(expiredTokenResponse.status()).toBe(401);

    // Step 4: Verify the error response body contains appropriate error details
    const expiredErrorBody = await expiredTokenResponse.json();
    expect(expiredErrorBody.error).toContain('Unauthorized');
    expect(expiredErrorBody.message).toMatch(/expired|invalid/i);

    // Step 5: Create a malformed token and send API request
    await page.fill('[data-testid="test-token-input"]', MALFORMED_TOKEN);
    const malformedTokenResponse = await page.request.get(`${BASE_URL}${API_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${MALFORMED_TOKEN}`
      }
    });

    // Step 6: Verify API returns 401 Unauthorized error for malformed token
    expect(malformedTokenResponse.status()).toBe(401);

    // Step 7: Verify the error response body for malformed token request
    const malformedErrorBody = await malformedTokenResponse.json();
    expect(malformedErrorBody.error).toContain('Unauthorized');

    // Step 8: Navigate to system logs or authentication logs section
    await page.goto(`${BASE_URL}/integration/settings`);
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="logs-container"]')).toBeVisible();

    // Step 9: Search for authentication failure entries for expired token
    await page.fill('[data-testid="log-search-input"]', 'authentication failure');
    await page.click('[data-testid="search-logs-button"]');
    const failedLogEntries = page.locator('[data-testid="log-entry"]:has-text("authentication failure")');;
    await expect(failedLogEntries.first()).toBeVisible();

    // Step 10: Verify failed attempts logged with timestamps
    await expect(failedLogEntries.first()).toContainText(/\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}/);

    // Step 11: Verify that no sensitive token information is exposed in the logs
    const logContent = await page.locator('[data-testid="logs-container"]').textContent();
    expect(logContent).not.toContain(EXPIRED_TOKEN);
    expect(logContent).not.toContain(MALFORMED_TOKEN);
    expect(logContent).not.toContain(VALID_CLIENT_SECRET);
  });

  test('Test automatic token refresh before expiry', async ({ page }) => {
    // Step 1: Configure valid credentials first
    await page.fill('[data-testid="client-id-input"]', VALID_CLIENT_ID);
    await page.fill('[data-testid="client-secret-input"]', VALID_CLIENT_SECRET);
    await page.click('[data-testid="save-credentials-button"]');
    await page.click('[data-testid="request-token-button"]');
    await page.waitForResponse(response => response.url().includes('/auth/token') && response.status() === 200);

    // Step 2: Check current access token and note its expiry time
    await expect(page.locator('[data-testid="token-expiry"]')).toBeVisible();
    const initialExpiryTime = await page.locator('[data-testid="token-expiry"]').textContent();

    // Step 3: Simulate token nearing expiry
    await page.click('[data-testid="simulate-token-expiry-button"]');
    await expect(page.locator('[data-testid="token-status"]')).toContainText('Token nearing expiry');

    // Step 4: Monitor system behavior and verify refresh token request
    const refreshResponse = page.waitForResponse(response => 
      response.url().includes('/auth/token') && 
      response.request().method() === 'POST' &&
      response.status() === 200
    );

    // Step 5: System triggers token refresh process
    await expect(page.locator('[data-testid="token-status"]')).toContainText('Refreshing token', { timeout: 10000 });
    await refreshResponse;

    // Step 6: Confirm new access token is received
    await expect(page.locator('[data-testid="token-status"]')).toContainText('Token refreshed successfully');

    // Step 7: Verify new token is stored securely
    const newExpiryTime = await page.locator('[data-testid="token-expiry"]').textContent();
    expect(newExpiryTime).not.toBe(initialExpiryTime);

    // Step 8: Make API call immediately after token refresh
    const newToken = await page.locator('[data-testid="access-token-value"]').textContent();
    const apiResponse = await page.request.get(`${BASE_URL}${API_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${newToken}`
      }
    });

    // Step 9: Verify API call succeeds without interruption
    expect(apiResponse.status()).toBe(200);

    // Step 10: Navigate to system logs and search for token refresh events
    await page.click('[data-testid="view-logs-button"]');
    await page.fill('[data-testid="log-search-input"]', 'token refresh');
    await page.click('[data-testid="search-logs-button"]');

    // Step 11: Verify log details include token refresh event with timestamp
    const refreshLogEntry = page.locator('[data-testid="log-entry"]:has-text("token refresh")').first();
    await expect(refreshLogEntry).toBeVisible();
    await expect(refreshLogEntry).toContainText(/\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}/);

    // Step 12: Verify log contains old and new token expiry information
    const logDetails = await refreshLogEntry.textContent();
    expect(logDetails).toMatch(/old.*expiry|previous.*expiry/i);
    expect(logDetails).toMatch(/new.*expiry/i);
  });
});