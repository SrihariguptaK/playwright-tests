import { test, expect } from '@playwright/test';

test.describe('Story-11: Establish Secure API Connections to Policy Rating Engine', () => {
  const BASE_URL = process.env.BASE_URL || 'https://insurance-system.example.com';
  const VALID_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'valid-client-id-12345';
  const VALID_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || 'valid-client-secret-67890';
  const INVALID_CLIENT_ID = 'invalid-client-id-xxxxx';
  const INVALID_CLIENT_SECRET = 'invalid-client-secret-yyyyy';

  test.beforeEach(async ({ page }) => {
    // Navigate to system administration panel
    await page.goto(`${BASE_URL}/admin/api-configuration`);
    await page.waitForLoadState('networkidle');
  });

  test('TC1: Validate successful API connection with valid credentials (happy-path)', async ({ page }) => {
    // Step 1: Navigate to API configuration settings
    await expect(page.locator('[data-testid="api-config-page"]')).toBeVisible();
    
    // Step 2: Enter valid OAuth 2.0 client ID
    await page.fill('[data-testid="oauth-client-id-input"]', VALID_CLIENT_ID);
    await expect(page.locator('[data-testid="oauth-client-id-input"]')).toHaveValue(VALID_CLIENT_ID);
    
    // Step 3: Enter valid OAuth 2.0 client secret
    await page.fill('[data-testid="oauth-client-secret-input"]', VALID_CLIENT_SECRET);
    await expect(page.locator('[data-testid="oauth-client-secret-input"]')).toHaveValue(VALID_CLIENT_SECRET);
    
    // Step 4: Click Save button to store credentials
    await page.click('[data-testid="save-credentials-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Credentials accepted without errors');
    
    // Step 5: Initiate API connection by clicking Test Connection
    await page.click('[data-testid="test-connection-button"]');
    await page.waitForTimeout(1500); // Wait for connection establishment
    
    // Step 6: Verify connection established securely over HTTPS
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');
    await expect(page.locator('[data-testid="connection-protocol"]')).toContainText('HTTPS');
    await expect(page.locator('[data-testid="ssl-status"]')).toContainText('Valid');
    
    // Step 7: Verify SSL/TLS certificate validation
    const certificateStatus = await page.locator('[data-testid="certificate-validation"]');
    await expect(certificateStatus).toBeVisible();
    await expect(certificateStatus).toContainText('Certificate Valid');
    
    // Step 8: Navigate to connection logs
    await page.click('[data-testid="view-logs-button"]');
    await expect(page.locator('[data-testid="connection-logs"]')).toBeVisible();
    
    // Step 9: Verify connection attempt logged with success status
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries.first()).toBeVisible();
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry).toContainText('success');
    await expect(firstLogEntry).toContainText('Connection established');
    
    // Step 10: Verify timestamp is present in log
    const timestamp = await firstLogEntry.locator('[data-testid="log-timestamp"]');
    await expect(timestamp).toBeVisible();
    
    // Step 11: Verify connection health monitoring is active
    await page.click('[data-testid="back-to-config-button"]');
    await expect(page.locator('[data-testid="health-monitoring-status"]')).toContainText('Active');
  });

  test('TC2: Verify connection retry on failure (error-case)', async ({ page }) => {
    // Step 1: Ensure API connection is initially disconnected
    const connectionStatus = page.locator('[data-testid="connection-status"]');
    await expect(connectionStatus).toContainText(/Disconnected|Idle/);
    
    // Step 2: Configure valid credentials first
    await page.fill('[data-testid="oauth-client-id-input"]', VALID_CLIENT_ID);
    await page.fill('[data-testid="oauth-client-secret-input"]', VALID_CLIENT_SECRET);
    await page.click('[data-testid="save-credentials-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 3: Enable network failure simulation
    await page.click('[data-testid="advanced-settings-toggle"]');
    await page.check('[data-testid="simulate-network-failure-checkbox"]');
    await expect(page.locator('[data-testid="simulate-network-failure-checkbox"]')).toBeChecked();
    
    // Step 4: Initiate API connection attempt
    await page.click('[data-testid="test-connection-button"]');
    
    // Step 5: Observe initial connection attempt failure
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="connection-attempt-count"]')).toContainText('Attempt 1 of 3');
    
    // Step 6: Monitor first retry attempt
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="connection-attempt-count"]')).toContainText('Attempt 2 of 3');
    
    // Step 7: Monitor second retry attempt
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="connection-attempt-count"]')).toContainText('Attempt 3 of 3');
    
    // Step 8: Monitor third and final retry attempt
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Failed');
    
    // Step 9: Verify delay between retry attempts is consistent
    await page.click('[data-testid="view-logs-button"]');
    const retryLogs = page.locator('[data-testid="log-entry"]:has-text("Retry")');
    await expect(retryLogs).toHaveCount(3);
    
    // Step 10: Navigate to error logs
    await page.click('[data-testid="filter-error-logs"]');
    await expect(page.locator('[data-testid="error-logs-section"]')).toBeVisible();
    
    // Step 11: Check error log entries for failed connection attempts
    const errorLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Connection failed' }).first();
    await expect(errorLogEntry).toBeVisible();
    await expect(errorLogEntry).toContainText('Retry count: 3');
    await expect(errorLogEntry).toContainText('Network failure');
    
    // Step 12: Verify error notification is generated
    await page.click('[data-testid="back-to-config-button"]');
    await expect(page.locator('[data-testid="error-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-notification"]')).toContainText('Connection failed after 3 retry attempts');
  });

  test('TC3: Ensure unauthorized access is rejected (error-case)', async ({ page }) => {
    // Step 1: Navigate to API configuration settings
    await expect(page.locator('[data-testid="api-config-page"]')).toBeVisible();
    
    // Step 2: Enter invalid OAuth 2.0 client ID
    await page.fill('[data-testid="oauth-client-id-input"]', INVALID_CLIENT_ID);
    await expect(page.locator('[data-testid="oauth-client-id-input"]')).toHaveValue(INVALID_CLIENT_ID);
    
    // Step 3: Enter invalid OAuth 2.0 client secret
    await page.fill('[data-testid="oauth-client-secret-input"]', INVALID_CLIENT_SECRET);
    await expect(page.locator('[data-testid="oauth-client-secret-input"]')).toHaveValue(INVALID_CLIENT_SECRET);
    
    // Step 4: Save the invalid credentials configuration
    await page.click('[data-testid="save-credentials-button"]');
    await page.waitForTimeout(500);
    
    // Step 5: Attempt to initiate API connection with invalid credentials
    await page.click('[data-testid="test-connection-button"]');
    await page.waitForTimeout(1500);
    
    // Step 6: Observe authentication response from authorization server
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Authentication Failed');
    
    // Step 7: Verify error message displayed to user
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/Invalid credentials|Authentication failed|Unauthorized/);
    
    // Step 8: Attempt to send test request to rating engine API
    const testRequestButton = page.locator('[data-testid="send-test-request-button"]');
    if (await testRequestButton.isVisible()) {
      await testRequestButton.click();
      await page.waitForTimeout(500);
    }
    
    // Step 9: Verify no API access is granted
    await expect(page.locator('[data-testid="api-access-status"]')).toContainText('Denied');
    await expect(page.locator('[data-testid="connection-status"]')).not.toContainText('Connected');
    
    // Step 10: Navigate to connection logs or security logs
    await page.click('[data-testid="view-logs-button"]');
    await page.click('[data-testid="security-logs-tab"]');
    await expect(page.locator('[data-testid="security-logs-section"]')).toBeVisible();
    
    // Step 11: Locate failed authentication attempt in logs
    const securityLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Authentication failed' }).first();
    await expect(securityLogEntry).toBeVisible();
    await expect(securityLogEntry).toContainText('Invalid credentials');
    await expect(securityLogEntry).toContainText('Unauthorized access attempt');
    
    // Step 12: Check system security alerts
    await page.click('[data-testid="security-alerts-button"]');
    await expect(page.locator('[data-testid="security-alerts-panel"]')).toBeVisible();
    
    const securityAlert = page.locator('[data-testid="security-alert"]').first();
    await expect(securityAlert).toBeVisible();
    await expect(securityAlert).toContainText(/Unauthorized access attempt|Failed authentication/);
    
    // Step 13: Verify alert is routed to security monitoring system
    await expect(securityAlert.locator('[data-testid="alert-status"]')).toContainText('Sent to Security Monitoring');
    
    // Step 14: Confirm no sensitive data or API access was granted
    await page.click('[data-testid="back-to-config-button"]');
    await expect(page.locator('[data-testid="data-access-log"]')).toContainText('No data accessed');
    await expect(page.locator('[data-testid="api-calls-count"]')).toContainText('0');
  });
});