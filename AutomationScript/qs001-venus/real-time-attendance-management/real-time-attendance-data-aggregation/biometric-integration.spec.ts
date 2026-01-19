import { test, expect } from '@playwright/test';

test.describe('Biometric Device Integration - Story 1', () => {
  let adminBaseUrl: string;

  test.beforeEach(async ({ page }) => {
    adminBaseUrl = process.env.ADMIN_URL || 'http://localhost:3000';
    // Login as administrator
    await page.goto(`${adminBaseUrl}/login`);
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test('Validate successful biometric data ingestion (happy-path)', async ({ page }) => {
    // Navigate to biometric device configuration section
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    await expect(page.locator('[data-testid="biometric-config-page"]')).toBeVisible();

    // Enter biometric device connection details
    await page.fill('[data-testid="api-endpoint-input"]', 'https://biometric-device.local/api/v1');
    await page.fill('[data-testid="api-key-input"]', 'test-api-key-12345');
    await page.fill('[data-testid="api-secret-input"]', 'test-api-secret-67890');
    await page.fill('[data-testid="polling-interval-input"]', '30');

    // Save connection settings
    await page.click('[data-testid="save-config-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Connection settings saved successfully');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected');

    // Simulate biometric attendance event
    await page.evaluate(() => {
      // Trigger test event via API or test endpoint
      fetch('/api/test/simulate-biometric-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          employeeId: 'EMP001',
          deviceId: 'BIO-DEVICE-01',
          timestamp: new Date().toISOString(),
          eventType: 'check-in'
        })
      });
    });

    // Wait for system to retrieve event data (within 1 minute)
    await page.waitForTimeout(5000);
    await page.click('[data-testid="data-ingestion-monitor"]');
    await expect(page.locator('[data-testid="latest-event"]')).toBeVisible({ timeout: 60000 });

    // Verify data stored in attendance database
    await page.click('[data-testid="attendance-records-link"]');
    await page.fill('[data-testid="search-employee-input"]', 'EMP001');
    await page.click('[data-testid="search-button"]');
    
    const latestRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(latestRecord).toBeVisible();
    await expect(latestRecord.locator('[data-testid="employee-id"]')).toContainText('EMP001');
    await expect(latestRecord.locator('[data-testid="event-type"]')).toContainText('check-in');
    await expect(latestRecord.locator('[data-testid="device-id"]')).toContainText('BIO-DEVICE-01');
    
    // Verify timestamp is recent (within last 2 minutes)
    const timestampText = await latestRecord.locator('[data-testid="timestamp"]').textContent();
    const recordTime = new Date(timestampText || '');
    const currentTime = new Date();
    const timeDiff = (currentTime.getTime() - recordTime.getTime()) / 1000;
    expect(timeDiff).toBeLessThan(120);
  });

  test('Verify retry mechanism on connection failure (error-case)', async ({ page }) => {
    // Navigate to biometric device configuration
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    await expect(page.locator('[data-testid="biometric-config-page"]')).toBeVisible();

    // Disable biometric device API temporarily
    await page.evaluate(() => {
      fetch('/api/test/disable-biometric-api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
    });

    await page.waitForTimeout(2000);

    // Navigate to system logs
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="system-logs-link"]');
    await expect(page.locator('[data-testid="system-logs-page"]')).toBeVisible();

    // Filter logs for biometric connection failures
    await page.selectOption('[data-testid="log-level-filter"]', 'ERROR');
    await page.fill('[data-testid="log-search-input"]', 'biometric connection');
    await page.click('[data-testid="apply-filter-button"]');

    // Verify connection failure is logged
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('connection failure');
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('biometric');

    // Wait for automatic retry attempts
    await page.waitForTimeout(5000);
    await page.click('[data-testid="refresh-logs-button"]');

    // Verify retry attempts are logged with timestamps
    const retryLogs = page.locator('[data-testid="log-entry"]:has-text("retry")');
    await expect(retryLogs.first()).toBeVisible();
    const retryCount = await retryLogs.count();
    expect(retryCount).toBeGreaterThan(0);

    // Verify timestamps are present in retry logs
    const firstRetryLog = await retryLogs.first().textContent();
    expect(firstRetryLog).toMatch(/\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}/);

    // Re-enable biometric device API
    await page.evaluate(() => {
      fetch('/api/test/enable-biometric-api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
    });

    await page.waitForTimeout(3000);

    // Monitor for successful reconnection
    await page.click('[data-testid="refresh-logs-button"]');
    await page.fill('[data-testid="log-search-input"]', 'biometric reconnect');
    await page.click('[data-testid="apply-filter-button"]');

    await expect(page.locator('[data-testid="log-entry"]:has-text("successfully reconnected")')).toBeVisible({ timeout: 30000 });

    // Verify data ingestion resumed
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="data-ingestion-monitor"]');
    await expect(page.locator('[data-testid="ingestion-status"]')).toContainText('Active');

    // Check admin dashboard for connection status
    await page.click('[data-testid="dashboard-link"]');
    await expect(page.locator('[data-testid="biometric-connection-status"]')).toContainText('Connected');
  });

  test('Ensure secure data transmission (edge-case)', async ({ page, context }) => {
    // Navigate to biometric configuration to trigger data transmission
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="biometric-config-link"]');
    await expect(page.locator('[data-testid="biometric-config-page"]')).toBeVisible();

    // Monitor network traffic for encryption
    const requests: any[] = [];
    page.on('request', request => {
      if (request.url().includes('biometric')) {
        requests.push({
          url: request.url(),
          method: request.method(),
          headers: request.headers()
        });
      }
    });

    // Trigger biometric attendance event
    await page.evaluate(() => {
      fetch('/api/test/simulate-biometric-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          employeeId: 'EMP002',
          deviceId: 'BIO-DEVICE-01',
          timestamp: new Date().toISOString(),
          eventType: 'check-in'
        })
      });
    });

    await page.waitForTimeout(3000);

    // Verify HTTPS protocol is used
    const biometricRequests = requests.filter(req => req.url.includes('biometric'));
    expect(biometricRequests.length).toBeGreaterThan(0);
    biometricRequests.forEach(req => {
      expect(req.url).toMatch(/^https:\/\//);
    });

    // Verify authentication headers present
    const authenticatedRequests = biometricRequests.filter(req => 
      req.headers['authorization'] || req.headers['x-api-key']
    );
    expect(authenticatedRequests.length).toBeGreaterThan(0);

    // Attempt unauthorized API access
    const unauthorizedResponse = await page.evaluate(async () => {
      const response = await fetch('/api/biometric/attendance', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
        // No authentication headers
      });
      return {
        status: response.status,
        statusText: response.statusText,
        body: await response.text()
      };
    });

    // Verify access denied
    expect(unauthorizedResponse.status).toBe(401);
    expect(unauthorizedResponse.body).toMatch(/unauthorized|access denied|authentication required/i);

    // Attempt access with expired token
    const expiredTokenResponse = await page.evaluate(async () => {
      const response = await fetch('/api/biometric/attendance', {
        method: 'GET',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer expired-token-12345'
        }
      });
      return {
        status: response.status,
        body: await response.text()
      };
    });

    expect(expiredTokenResponse.status).toBe(401);
    expect(expiredTokenResponse.body).toMatch(/expired|invalid token/i);

    // Navigate to audit logs
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Search for unauthorized access attempts
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized');
    await page.click('[data-testid="apply-audit-filter-button"]');

    // Verify unauthorized attempts are logged
    const unauthorizedLogs = page.locator('[data-testid="audit-entry"]:has-text("unauthorized")');
    await expect(unauthorizedLogs.first()).toBeVisible();
    const unauthorizedCount = await unauthorizedLogs.count();
    expect(unauthorizedCount).toBeGreaterThanOrEqual(2);

    // Verify successful authentication attempts are also logged
    await page.fill('[data-testid="audit-search-input"]', 'authentication success');
    await page.click('[data-testid="apply-audit-filter-button"]');

    const successLogs = page.locator('[data-testid="audit-entry"]:has-text("success")');
    await expect(successLogs.first()).toBeVisible();

    // Verify audit log entries contain required information
    const firstAuditEntry = await successLogs.first().textContent();
    expect(firstAuditEntry).toMatch(/\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}/);
    expect(firstAuditEntry).toBeTruthy();
  });
});