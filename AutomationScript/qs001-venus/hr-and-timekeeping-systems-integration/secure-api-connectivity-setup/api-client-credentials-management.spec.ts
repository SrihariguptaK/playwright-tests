import { test, expect } from '@playwright/test';

test.describe('API Client Credentials Management', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const UNAUTHORIZED_EMAIL = 'user@example.com';
  const UNAUTHORIZED_PASSWORD = 'UserPass123!';
  let clientId: string;
  let clientSecret: string;

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Verify creation and storage of API client credentials (happy-path)', async ({ page, request }) => {
    // Navigate to API client management section in the management console
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    await page.click('[data-testid="api-clients-menu"]');
    await expect(page).toHaveURL(/.*api-clients/);

    // Create new API client credentials via management console
    await page.click('[data-testid="create-client-button"]');
    await page.fill('[data-testid="client-name-input"]', 'Test API Client');
    await page.fill('[data-testid="client-description-input"]', 'Test client for automation');
    await page.selectOption('[data-testid="client-scope-select"]', 'read:write');
    await page.click('[data-testid="submit-client-button"]');

    // Verify credentials are generated and stored securely
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('API client credentials created successfully');

    // Capture generated credentials
    clientId = await page.locator('[data-testid="client-id-display"]').textContent() || '';
    clientSecret = await page.locator('[data-testid="client-secret-display"]').textContent() || '';
    expect(clientId).toBeTruthy();
    expect(clientSecret).toBeTruthy();

    // Verify credentials are stored in the credential store by checking the client list
    await page.click('[data-testid="close-credentials-modal"]');
    await expect(page.locator(`[data-testid="client-row-${clientId}"]`)).toBeVisible();
    await expect(page.locator(`[data-testid="client-row-${clientId}"]`)).toContainText('Test API Client');

    // Use the newly created credentials to make an API request to a test endpoint
    const apiResponse = await request.get(`${BASE_URL}/api/test`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify access granted with valid credentials
    expect(apiResponse.status()).toBe(200);
    const responseBody = await apiResponse.json();
    expect(responseBody.authenticated).toBe(true);

    // Verify audit log entry for credential creation
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    await page.fill('[data-testid="search-logs-input"]', clientId);
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('API client created');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(clientId);
  });

  test('Verify credential rotation and revocation (happy-path)', async ({ page, request }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to API client management
    await page.click('[data-testid="api-clients-menu"]');
    await expect(page).toHaveURL(/.*api-clients/);

    // Create a test client first
    await page.click('[data-testid="create-client-button"]');
    await page.fill('[data-testid="client-name-input"]', 'Rotation Test Client');
    await page.fill('[data-testid="client-description-input"]', 'Client for rotation testing');
    await page.click('[data-testid="submit-client-button"]');

    const oldClientId = await page.locator('[data-testid="client-id-display"]').textContent() || '';
    const oldClientSecret = await page.locator('[data-testid="client-secret-display"]').textContent() || '';
    await page.click('[data-testid="close-credentials-modal"]');

    // Select an existing API client and initiate credential rotation
    await page.click(`[data-testid="client-row-${oldClientId}"]`);
    await page.click('[data-testid="rotate-credentials-button"]');
    await page.click('[data-testid="confirm-rotation-button"]');

    // Verify old credentials are revoked and new credentials are active
    await expect(page.locator('[data-testid="rotation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rotation-success-message"]')).toContainText('Credentials rotated successfully');

    const newClientSecret = await page.locator('[data-testid="new-client-secret-display"]').textContent() || '';
    expect(newClientSecret).toBeTruthy();
    expect(newClientSecret).not.toBe(oldClientSecret);
    await page.click('[data-testid="close-credentials-modal"]');

    // Verify old credentials are revoked by checking credential status
    await expect(page.locator(`[data-testid="client-status-${oldClientId}"]`)).toContainText('Active');

    // Attempt to make an API request using the revoked (old) credentials
    const oldCredentialsResponse = await request.get(`${BASE_URL}/api/test`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${oldClientId}:${oldClientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify access denied with revoked credentials
    expect(oldCredentialsResponse.status()).toBe(401);
    const oldCredentialsBody = await oldCredentialsResponse.json();
    expect(oldCredentialsBody.error).toContain('Invalid or revoked credentials');

    // Make an API request using the new credentials
    const newCredentialsResponse = await request.get(`${BASE_URL}/api/test`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${oldClientId}:${newClientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify access granted with new credentials
    expect(newCredentialsResponse.status()).toBe(200);
    const newCredentialsBody = await newCredentialsResponse.json();
    expect(newCredentialsBody.authenticated).toBe(true);

    // Review audit logs for credential rotation activity
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    await page.fill('[data-testid="search-logs-input"]', oldClientId);
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Credentials rotated');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText(oldClientId);
  });

  test('Verify access control to credential management (error-case)', async ({ page, request }) => {
    // Log into the system using unauthorized user credentials
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the credential management section
    const apiClientsMenu = page.locator('[data-testid="api-clients-menu"]');
    
    // Verify menu is not visible or disabled for unauthorized users
    await expect(apiClientsMenu).not.toBeVisible().catch(async () => {
      // If menu is visible, clicking should show access denied
      await apiClientsMenu.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    });

    // Attempt to directly navigate to credential management URL
    await page.goto(`${BASE_URL}/api-clients`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('You do not have permission to access this resource');

    // Get auth token for unauthorized user
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || '';

    // Attempt to directly access credential management API endpoint without proper authorization
    const unauthorizedApiResponse = await request.get(`${BASE_URL}/api/clients`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify access denied at API level
    expect(unauthorizedApiResponse.status()).toBe(403);
    const unauthorizedBody = await unauthorizedApiResponse.json();
    expect(unauthorizedBody.error).toContain('Insufficient permissions');

    // Verify audit log captures the unauthorized access attempt
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    await page.fill('[data-testid="search-logs-input"]', UNAUTHORIZED_EMAIL);
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('api-clients');
  });
});