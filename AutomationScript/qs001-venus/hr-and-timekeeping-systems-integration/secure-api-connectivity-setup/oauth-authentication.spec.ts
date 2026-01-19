import { test, expect } from '@playwright/test';
import { request } from '@playwright/test';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
const OAUTH_TOKEN_ENDPOINT = `${API_BASE_URL}/oauth/token`;
const SECURED_API_ENDPOINT = `${API_BASE_URL}/api/employees`;
const VALID_CLIENT_ID = process.env.CLIENT_ID || 'test_client_id';
const VALID_CLIENT_SECRET = process.env.CLIENT_SECRET || 'test_client_secret';

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

interface AuthLog {
  timestamp: string;
  client_id: string;
  event_type: string;
  status: string;
}

test.describe('OAuth 2.0 Authentication Implementation', () => {
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
    const logsResponse = await apiContext.get(`${API_BASE_URL}/api/auth/logs`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      params: {
        client_id: VALID_CLIENT_ID,
        event_type: 'token_issued'
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
    const apiResponse = await apiContext.get(SECURED_API_ENDPOINT);

    expect(apiResponse.ok()).toBeFalsy();
    expect(apiResponse.status()).toBe(401);

    const errorData = await apiResponse.json();
    expect(errorData.error).toBeDefined();
    expect(errorData.error).toContain('Unauthorized');

    // Step 2: Check logs for unauthorized access attempt
    // First, get a valid token to access the logs endpoint
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Query logs for unauthorized attempt
    const currentTimestamp = new Date().toISOString();
    const logsResponse = await apiContext.get(`${API_BASE_URL}/api/auth/logs`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      params: {
        event_type: 'unauthorized_access',
        endpoint: '/api/employees',
        timestamp_from: new Date(Date.now() - 60000).toISOString()
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logs: AuthLog[] = await logsResponse.json();
    expect(logs.length).toBeGreaterThan(0);

    const unauthorizedLog = logs.find(log => 
      log.event_type === 'unauthorized_access' && 
      log.status === 'failed'
    );
    expect(unauthorizedLog).toBeDefined();
    expect(unauthorizedLog!.timestamp).toBeDefined();
  });

  test('Reject API request with expired token', async () => {
    // Use a pre-expired token or mock expired token
    const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY2xpZW50X2lkIjoidGVzdF9jbGllbnQiLCJleHAiOjE1MTYyMzkwMjJ9.expired_signature';

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
    expect(errorData.error.toLowerCase()).toMatch(/expired|unauthorized/);

    // Step 2: Query authentication logs for expired token rejection event
    // Get a valid token to access logs
    const tokenResponse = await apiContext.post(OAUTH_TOKEN_ENDPOINT, {
      data: {
        grant_type: 'client_credentials',
        client_id: VALID_CLIENT_ID,
        client_secret: VALID_CLIENT_SECRET
      }
    });

    const tokenData: OAuthTokenResponse = await tokenResponse.json();
    const validAccessToken = tokenData.access_token;

    const logsResponse = await apiContext.get(`${API_BASE_URL}/api/auth/logs`, {
      headers: {
        'Authorization': `Bearer ${validAccessToken}`
      },
      params: {
        event_type: 'token_expired',
        timestamp_from: new Date(Date.now() - 60000).toISOString()
      }
    });

    expect(logsResponse.ok()).toBeTruthy();
    const logs: AuthLog[] = await logsResponse.json();
    expect(logs.length).toBeGreaterThan(0);

    const expiredTokenLog = logs.find(log => 
      log.event_type === 'token_expired' && 
      log.status === 'rejected'
    );
    expect(expiredTokenLog).toBeDefined();
    expect(expiredTokenLog!.timestamp).toBeDefined();
  });
});