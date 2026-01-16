import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'https://api.example.com';
const ADMIN_URL = process.env.ADMIN_URL || 'https://admin.example.com';
const CLIENT_ID = process.env.CLIENT_ID || 'test-client-id';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'test-client-secret';
const EXTERNAL_PROVIDER_URL = process.env.EXTERNAL_PROVIDER_URL || 'https://external-idp.example.com';

test.describe('OAuth 2.0 Authentication for API Integrations', () => {
  
  test('Validate OAuth 2.0 token issuance and validation (happy-path)', async ({ page, request }) => {
    // Navigate to OAuth authorization endpoint and initiate authorization flow with valid client credentials
    await page.goto(`${BASE_URL}/oauth/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${BASE_URL}/callback`);
    
    await page.fill('[data-testid="client-id-input"]', CLIENT_ID);
    await page.fill('[data-testid="client-secret-input"]', CLIENT_SECRET);
    await page.click('[data-testid="authorize-button"]');
    
    // Wait for redirect and capture authorization code
    await page.waitForURL(/.*callback.*code=.*/);
    const url = page.url();
    const authCode = new URL(url).searchParams.get('code');
    expect(authCode).toBeTruthy();
    
    // Complete authorization and request access token via /oauth/token endpoint
    const tokenResponse = await request.post(`${BASE_URL}/oauth/token`, {
      data: {
        grant_type: 'authorization_code',
        code: authCode,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: `${BASE_URL}/callback`
      }
    });
    
    expect(tokenResponse.ok()).toBeTruthy();
    const tokenData = await tokenResponse.json();
    expect(tokenData.access_token).toBeTruthy();
    expect(tokenData.token_type).toBe('Bearer');
    const accessToken = tokenData.access_token;
    
    // Make API call to a protected endpoint with the valid access token in Authorization header
    const startTime = Date.now();
    const apiResponse = await request.get(`${BASE_URL}/api/protected/resource`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    const validationTime = Date.now() - startTime;
    
    expect(apiResponse.ok()).toBeTruthy();
    expect(apiResponse.status()).toBe(200);
    
    // Verify token validation response time is under 100ms
    expect(validationTime).toBeLessThan(100);
    
    // Wait for token to expire or manually set system time beyond token expiry
    // Simulate expired token by using an invalid token
    const expiredToken = 'expired.token.value';
    
    // Make API call to the same protected endpoint with the expired token
    const expiredResponse = await request.get(`${BASE_URL}/api/protected/resource`, {
      headers: {
        'Authorization': `Bearer ${expiredToken}`
      }
    });
    
    expect(expiredResponse.ok()).toBeFalsy();
    expect(expiredResponse.status()).toBe(401);
    const errorData = await expiredResponse.json();
    expect(errorData.error).toContain('unauthorized');
  });
  
  test('Verify logging of authentication events (happy-path)', async ({ page, request }) => {
    // Perform OAuth authentication flow with valid credentials and obtain access token
    const tokenResponse = await request.post(`${BASE_URL}/oauth/token`, {
      data: {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
      }
    });
    
    expect(tokenResponse.ok()).toBeTruthy();
    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;
    const authTimestamp = Date.now();
    
    // Navigate to authentication logs dashboard and search for the recent authentication event
    await page.goto(`${ADMIN_URL}/logs/authentication`);
    await page.waitForSelector('[data-testid="auth-logs-table"]');
    
    await page.fill('[data-testid="log-search-input"]', CLIENT_ID);
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Verify authentication success event is logged
    const successLogRow = page.locator('[data-testid="log-entry"]').filter({ hasText: 'success' }).first();
    await expect(successLogRow).toBeVisible();
    
    const logTimestamp = await successLogRow.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    const logStatus = await successLogRow.locator('[data-testid="log-status"]').textContent();
    expect(logStatus).toContain('success');
    
    // Attempt authentication with an invalid or malformed token
    const invalidToken = 'invalid.malformed.token';
    const failedResponse = await request.get(`${BASE_URL}/api/protected/resource`, {
      headers: {
        'Authorization': `Bearer ${invalidToken}`
      }
    });
    
    expect(failedResponse.status()).toBe(401);
    
    // Check authentication logs for the failed attempt
    await page.reload();
    await page.waitForSelector('[data-testid="auth-logs-table"]');
    await page.fill('[data-testid="log-search-input"]', 'failure');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    const failureLogRow = page.locator('[data-testid="log-entry"]').filter({ hasText: 'failure' }).first();
    await expect(failureLogRow).toBeVisible();
    
    const failureStatus = await failureLogRow.locator('[data-testid="log-status"]').textContent();
    expect(failureStatus).toContain('failure');
    
    // Review authentication logs for completeness and accuracy
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(0);
    
    for (let i = 0; i < Math.min(logCount, 5); i++) {
      const entry = logEntries.nth(i);
      await expect(entry.locator('[data-testid="log-timestamp"]')).toBeVisible();
      await expect(entry.locator('[data-testid="log-status"]')).toBeVisible();
      await expect(entry.locator('[data-testid="log-details"]')).toBeVisible();
    }
    
    // Verify log entries are immutable and cannot be modified
    const firstLogEntry = logEntries.first();
    const editButton = firstLogEntry.locator('[data-testid="edit-log-button"]');
    await expect(editButton).not.toBeVisible();
    
    const deleteButton = firstLogEntry.locator('[data-testid="delete-log-button"]');
    await expect(deleteButton).not.toBeVisible();
  });
  
  test('Test integration with external identity provider (happy-path)', async ({ page, request }) => {
    // Navigate to admin console and access identity provider configuration section
    await page.goto(`${ADMIN_URL}/settings/identity-providers`);
    await page.waitForSelector('[data-testid="identity-provider-config"]');
    
    // Enter external identity provider settings
    await page.click('[data-testid="add-provider-button"]');
    await page.waitForSelector('[data-testid="provider-form"]');
    
    await page.fill('[data-testid="provider-name-input"]', 'External IDP');
    await page.fill('[data-testid="provider-url-input"]', EXTERNAL_PROVIDER_URL);
    await page.fill('[data-testid="provider-client-id-input"]', 'external-client-id');
    await page.fill('[data-testid="provider-client-secret-input"]', 'external-client-secret');
    await page.fill('[data-testid="provider-scopes-input"]', 'openid profile email');
    
    // Save the identity provider configuration
    await page.click('[data-testid="save-provider-button"]');
    await page.waitForSelector('[data-testid="success-message"]');
    
    const successMessage = await page.locator('[data-testid="success-message"]').textContent();
    expect(successMessage).toContain('saved');
    
    // Verify settings are saved and applied
    await page.reload();
    await page.waitForSelector('[data-testid="identity-provider-config"]');
    
    const providerRow = page.locator('[data-testid="provider-row"]').filter({ hasText: 'External IDP' });
    await expect(providerRow).toBeVisible();
    
    // Initiate OAuth authorization flow using the external identity provider
    await page.goto(`${BASE_URL}/oauth/authorize?client_id=external-client-id&response_type=code&redirect_uri=${BASE_URL}/callback&provider=external`);
    
    // Complete authentication on external provider and authorize the application
    await page.waitForSelector('[data-testid="external-login-form"]');
    await page.fill('[data-testid="external-username-input"]', 'testuser@external.com');
    await page.fill('[data-testid="external-password-input"]', 'ExternalPass123!');
    await page.click('[data-testid="external-login-button"]');
    
    await page.waitForSelector('[data-testid="authorize-app-button"]');
    await page.click('[data-testid="authorize-app-button"]');
    
    // Wait for redirect and capture authorization code
    await page.waitForURL(/.*callback.*code=.*/);
    const url = page.url();
    const authCode = new URL(url).searchParams.get('code');
    expect(authCode).toBeTruthy();
    
    // Request token via external provider
    const tokenResponse = await request.post(`${BASE_URL}/oauth/token`, {
      data: {
        grant_type: 'authorization_code',
        code: authCode,
        client_id: 'external-client-id',
        client_secret: 'external-client-secret',
        redirect_uri: `${BASE_URL}/callback`,
        provider: 'external'
      }
    });
    
    expect(tokenResponse.ok()).toBeTruthy();
    const tokenData = await tokenResponse.json();
    expect(tokenData.access_token).toBeTruthy();
    const externalToken = tokenData.access_token;
    
    // Verify the external token is accepted and stored by the system
    expect(tokenData.provider).toBe('external');
    
    // Make API call to a protected endpoint using the external provider token
    const apiResponse = await request.get(`${BASE_URL}/api/protected/resource`, {
      headers: {
        'Authorization': `Bearer ${externalToken}`
      }
    });
    
    expect(apiResponse.ok()).toBeTruthy();
    expect(apiResponse.status()).toBe(200);
    
    // Verify authentication event is logged with external provider details
    await page.goto(`${ADMIN_URL}/logs/authentication`);
    await page.waitForSelector('[data-testid="auth-logs-table"]');
    
    await page.fill('[data-testid="log-search-input"]', 'external');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    const externalLogRow = page.locator('[data-testid="log-entry"]').filter({ hasText: 'External IDP' }).first();
    await expect(externalLogRow).toBeVisible();
    
    const providerDetails = await externalLogRow.locator('[data-testid="log-provider"]').textContent();
    expect(providerDetails).toContain('External IDP');
    
    const logStatus = await externalLogRow.locator('[data-testid="log-status"]').textContent();
    expect(logStatus).toContain('success');
  });
  
});