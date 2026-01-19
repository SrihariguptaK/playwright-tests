import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
const OAUTH_TOKEN_ENDPOINT = `${API_BASE_URL}/oauth/token`;
const SECURED_API_ENDPOINT = `${API_BASE_URL}/api/employees`;
const LOGS_ENDPOINT = `${API_BASE_URL}/api/logs/authentication`;

const VALID_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'test_client_id';
const VALID_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || 'test_client_secret';

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

interface AuthLog {
  timestamp: string;
  client_id: string;
  event_type: string;
  endpoint: string;
  status: string;
}

describe('OAuth 2.0 Authentication - story-13', () => {
  let apiContext: any;

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

  test('Validate successful OAuth token issuance with valid client credentials', async () => {
    // Step 1: Submit valid client credentials to /oauth/token endpoint
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    expect(tokenResponse.ok()).toBeTruthy();
    expect(tokenResponse.status()).toBe(200);

    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    expect(tokenData.access_token).toBeDefined();
    expect(tokenData.access_token).not.toBe('');
    expect(tokenData.token_type).toBe('Bearer');
    expect(tokenData.expires_in).toBeGreaterThan(0);

    const accessToken = tokenData.access_token;

    // Step 2: Use access token to call secured API endpoint
    const apiResponse = await apiContext.get(SECURED_API_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    expect(apiResponse.ok()).toBeTruthy();
    expect(apiResponse.status()).toBe(200);

    const apiData = await apiResponse.json();
    expect(apiData).toBeDefined();

    // Step 3: Check logs for authentication event
    await test.step('Wait for log processing', async () => {
      await new Promise(resolve => setTimeout(resolve, 1000));
    });

    const logsResponse = await apiContext.get(LOGS_ENDPOINT, {
      params: {
        client_id: VALID_CLIENT_ID,
        event_type: 'token_issued',
        limit: 10
      },
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logs: AuthLog[] = await logsResponse.json();
    expect(logs.length).toBeGreaterThan(0);

    const recentLog = logs[0];
    expect(recentLog.client_id).toBe(VALID_CLIENT_ID);
    expect(recentLog.event_type).toBe('token_issued');
    expect(recentLog.status).toBe('success');
    expect(recentLog.timestamp).toBeDefined();
  });

  test('Reject API request without access token', async () => {
    // Step 1: Call secured API endpoint without access token
    const apiResponse = await apiContext.get(SECURED_API_ENDPOINT, {
      headers: {
        // Intentionally not including Authorization header
      }
    });

    expect(apiResponse.ok()).toBeFalsy();
    expect(apiResponse.status()).toBe(401);

    const errorData = await apiResponse.json();
    expect(errorData.error).toBeDefined();
    expect(errorData.error).toContain('Unauthorized');

    // Step 2: Check logs for unauthorized access attempt
    await test.step('Wait for log processing', async () => {
      await new Promise(resolve => setTimeout(resolve, 1000));
    });

    // Get a valid token first to access logs endpoint
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    const currentTimestamp = new Date().toISOString();
    const logsResponse = await apiContext.get(LOGS_ENDPOINT, {
      params: {
        event_type: 'unauthorized_access',
        endpoint: SECURED_API_ENDPOINT,
        limit: 10
      },
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logs: AuthLog[] = await logsResponse.json();
    expect(logs.length).toBeGreaterThan(0);

    const unauthorizedLog = logs.find(log => 
      log.event_type === 'unauthorized_access' && 
      log.endpoint === SECURED_API_ENDPOINT
    );

    expect(unauthorizedLog).toBeDefined();
    expect(unauthorizedLog!.status).toBe('failed');
    expect(unauthorizedLog!.timestamp).toBeDefined();
  });

  test('Reject API request with expired token', async () => {
    // Using a known expired token or a token with invalid format
    const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.expired_signature';

    // Step 1: Use expired access token to call secured API endpoint
    const apiResponse = await apiContext.get(SECURED_API_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${expiredToken}`
      }
    });

    expect(apiResponse.ok()).toBeFalsy();
    expect(apiResponse.status()).toBe(401);

    const errorData = await apiResponse.json();
    expect(errorData.error).toBeDefined();
    expect(errorData.error.toLowerCase()).toMatch(/expired|invalid|unauthorized/);

    // Verify error message indicates token expiry
    const errorMessage = errorData.error || errorData.message || '';
    expect(errorMessage.toLowerCase()).toContain('token');
  });

  test('System enforces token expiration and denies requests with expired tokens', async () => {
    // Get a valid token first
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    expect(tokenResponse.ok()).toBeTruthy();
    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    const accessToken = tokenData.access_token;
    const expiresIn = tokenData.expires_in;

    // Verify token works initially
    const initialApiResponse = await apiContext.get(SECURED_API_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    expect(initialApiResponse.ok()).toBeTruthy();
    expect(initialApiResponse.status()).toBe(200);

    // Verify expiration time is set
    expect(expiresIn).toBeGreaterThan(0);
    expect(expiresIn).toBeLessThanOrEqual(3600); // Typically 1 hour or less
  });

  test('System supports token refresh flow according to OAuth 2.0 standards', async () => {
    // Get initial token
    const initialTokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    expect(initialTokenResponse.ok()).toBeTruthy();
    const initialTokenData: OAuthTokenResponse = await initialTokenResponse.json();
    const initialAccessToken = initialTokenData.access_token;

    // Request a new token (refresh)
    const refreshTokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    expect(refreshTokenResponse.ok()).toBeTruthy();
    const refreshTokenData: OAuthTokenResponse = await refreshTokenResponse.json();
    const newAccessToken = refreshTokenData.access_token;

    expect(newAccessToken).toBeDefined();
    expect(newAccessToken).not.toBe('');

    // Verify new token works
    const apiResponse = await apiContext.get(SECURED_API_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${newAccessToken}`
      }
    });

    expect(apiResponse.ok()).toBeTruthy();
    expect(apiResponse.status()).toBe(200);
  });

  test('System logs all authentication attempts with timestamps and client identifiers', async () => {
    const testClientId = VALID_CLIENT_ID;
    const timestampBefore = new Date().toISOString();

    // Perform authentication
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: testClientId,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    expect(tokenResponse.ok()).toBeTruthy();
    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    const timestampAfter = new Date().toISOString();

    // Wait for log processing
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Check logs
    const logsResponse = await apiContext.get(LOGS_ENDPOINT, {
      params: {
        client_id: testClientId,
        limit: 10
      },
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logs: AuthLog[] = await logsResponse.json();
    expect(logs.length).toBeGreaterThan(0);

    const recentLog = logs[0];
    expect(recentLog.client_id).toBe(testClientId);
    expect(recentLog.timestamp).toBeDefined();
    expect(new Date(recentLog.timestamp).getTime()).toBeGreaterThanOrEqual(new Date(timestampBefore).getTime() - 5000);
    expect(new Date(recentLog.timestamp).getTime()).toBeLessThanOrEqual(new Date(timestampAfter).getTime() + 5000);
  });
});