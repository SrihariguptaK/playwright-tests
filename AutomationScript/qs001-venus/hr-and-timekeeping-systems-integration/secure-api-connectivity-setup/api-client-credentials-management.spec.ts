import { test, expect } from '@playwright/test';

test.describe('API Client Credentials Management', () => {
  let baseURL: string;
  let adminUsername: string;
  let adminPassword: string;
  let generatedClientId: string;
  let generatedClientSecret: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    adminUsername = process.env.ADMIN_USERNAME || 'admin@example.com';
    adminPassword = process.env.ADMIN_PASSWORD || 'AdminPass123!';

    // Login as System Administrator
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', adminUsername);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Verify creation and storage of API client credentials', async ({ page, request }) => {
    // Navigate to credential management console
    await page.goto(`${baseURL}/admin/api-clients`);
    await expect(page.locator('[data-testid="api-clients-page"]')).toBeVisible();

    // Action: Create new API client credentials via management console
    await page.click('[data-testid="create-client-button"]');
    await expect(page.locator('[data-testid="create-client-modal"]')).toBeVisible();

    const clientName = `test-client-${Date.now()}`;
    await page.fill('[data-testid="client-name-input"]', clientName);
    await page.fill('[data-testid="client-description-input"]', 'Test API client for automation');
    await page.click('[data-testid="submit-create-client"]');

    // Expected Result: Credentials are generated and stored securely
    await expect(page.locator('[data-testid="success-message"]')).toContainText('API client credentials created successfully');
    
    // Capture generated credentials
    const clientIdElement = page.locator('[data-testid="generated-client-id"]');
    const clientSecretElement = page.locator('[data-testid="generated-client-secret"]');
    await expect(clientIdElement).toBeVisible();
    await expect(clientSecretElement).toBeVisible();

    generatedClientId = await clientIdElement.textContent() || '';
    generatedClientSecret = await clientSecretElement.textContent() || '';

    expect(generatedClientId).toBeTruthy();
    expect(generatedClientSecret).toBeTruthy();
    expect(generatedClientSecret.length).toBeGreaterThan(20);

    // Close credentials modal
    await page.click('[data-testid="close-credentials-modal"]');

    // Verify client appears in the list
    await expect(page.locator(`[data-testid="client-row-${generatedClientId}"]`)).toBeVisible();
    await expect(page.locator(`[data-testid="client-row-${generatedClientId}"]`)).toContainText(clientName);

    // Action: Use credentials to access API
    const apiResponse = await request.get(`${baseURL}/api/protected-resource`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${generatedClientId}:${generatedClientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });

    // Expected Result: Access granted with valid credentials
    expect(apiResponse.status()).toBe(200);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('data');
  });

  test('Verify credential rotation and revocation', async ({ page, request }) => {
    // Setup: Create initial credentials
    await page.goto(`${baseURL}/admin/api-clients`);
    await page.click('[data-testid="create-client-button"]');
    
    const clientName = `rotation-test-${Date.now()}`;
    await page.fill('[data-testid="client-name-input"]', clientName);
    await page.fill('[data-testid="client-description-input"]', 'Client for rotation testing');
    await page.click('[data-testid="submit-create-client"]');

    const oldClientId = await page.locator('[data-testid="generated-client-id"]').textContent() || '';
    const oldClientSecret = await page.locator('[data-testid="generated-client-secret"]').textContent() || '';
    await page.click('[data-testid="close-credentials-modal"]');

    // Action: Rotate API client credentials
    await page.click(`[data-testid="client-row-${oldClientId}"]`);
    await page.click('[data-testid="rotate-credentials-button"]');
    await expect(page.locator('[data-testid="rotate-confirmation-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-rotate-button"]');

    // Expected Result: Old credentials revoked and new credentials active
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Credentials rotated successfully');
    
    const newClientSecret = await page.locator('[data-testid="new-client-secret"]').textContent() || '';
    expect(newClientSecret).toBeTruthy();
    expect(newClientSecret).not.toBe(oldClientSecret);
    await page.click('[data-testid="close-credentials-modal"]');

    // Verify new credentials work
    const newApiResponse = await request.get(`${baseURL}/api/protected-resource`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${oldClientId}:${newClientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });
    expect(newApiResponse.status()).toBe(200);

    // Action: Attempt API access with revoked credentials
    const oldApiResponse = await request.get(`${baseURL}/api/protected-resource`, {
      headers: {
        'Authorization': `Bearer ${Buffer.from(`${oldClientId}:${oldClientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json'
      }
    });

    // Expected Result: Access denied
    expect(oldApiResponse.status()).toBe(401);
    const errorBody = await oldApiResponse.json();
    expect(errorBody.error).toContain('Invalid or revoked credentials');
  });

  test('Verify access control to credential management', async ({ page, context }) => {
    // Logout from admin account
    await page.goto(`${baseURL}/admin/api-clients`);
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Login as unauthorized user (regular user without admin privileges)
    const regularUsername = process.env.REGULAR_USERNAME || 'user@example.com';
    const regularPassword = process.env.REGULAR_PASSWORD || 'UserPass123!';

    await page.fill('[data-testid="username-input"]', regularUsername);
    await page.fill('[data-testid="password-input"]', regularPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Action: Attempt to access credential management as unauthorized user
    await page.goto(`${baseURL}/admin/api-clients`);

    // Expected Result: Access denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access this resource');

    // Verify user is redirected or page shows 403 error
    const currentUrl = page.url();
    const isAccessDenied = currentUrl.includes('access-denied') || currentUrl.includes('403');
    expect(isAccessDenied || await page.locator('[data-testid="access-denied-message"]').isVisible()).toBeTruthy();

    // Verify credential management UI elements are not accessible
    await expect(page.locator('[data-testid="create-client-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="api-clients-table"]')).not.toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Logout after each test
    await page.goto(`${baseURL}/admin/api-clients`);
    const userMenu = page.locator('[data-testid="user-menu"]');
    if (await userMenu.isVisible()) {
      await userMenu.click();
      await page.click('[data-testid="logout-button"]');
    }
  });
});