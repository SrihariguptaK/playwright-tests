import { test, expect } from '@playwright/test';

test.describe('Badge Scan System Integration - Story 14', () => {
  let baseURL: string;
  let adminUsername: string;
  let adminPassword: string;
  let badgeScanAPIEndpoint: string;
  let badgeScanAPIKey: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    adminUsername = process.env.ADMIN_USERNAME || 'admin@attendance.com';
    adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123';
    badgeScanAPIEndpoint = process.env.BADGE_SCAN_API || 'https://badge-scan-api.example.com/v1';
    badgeScanAPIKey = process.env.BADGE_SCAN_API_KEY || 'test-api-key-12345';

    // Login to admin interface
    await page.goto(`${baseURL}/admin/login`);
    await page.fill('[data-testid="username-input"]', adminUsername);
    await page.fill('[data-testid="password-input"]', adminPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
  });

  test('Validate successful badge scan data ingestion (happy-path)', async ({ page }) => {
    // Navigate to badge scan system integration configuration section
    await page.click('[data-testid="integrations-menu"]');
    await page.click('[data-testid="badge-scan-integration"]');
    await expect(page.locator('[data-testid="badge-scan-config-section"]')).toBeVisible();

    // Enter badge scan system API endpoint URL
    await page.fill('[data-testid="api-endpoint-input"]', badgeScanAPIEndpoint);

    // Enter authentication credentials
    await page.fill('[data-testid="api-key-input"]', badgeScanAPIKey);

    // Enter badge scan system identifier and location information
    await page.fill('[data-testid="system-identifier-input"]', 'BADGE-SYSTEM-001');
    await page.fill('[data-testid="location-input"]', 'Main Office - Floor 1');

    // Click Test Connection button
    await page.click('[data-testid="test-connection-button"]');
    await expect(page.locator('[data-testid="connection-status"]')).toContainText('Connected', { timeout: 10000 });
    await expect(page.locator('[data-testid="connection-success-message"]')).toBeVisible();

    // Save the badge scan system configuration
    await page.click('[data-testid="save-config-button"]');
    await expect(page.locator('[data-testid="config-saved-notification"]')).toBeVisible();

    // Navigate to real-time data monitoring dashboard
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="realtime-data-dashboard"]');
    await expect(page.locator('[data-testid="realtime-dashboard"]')).toBeVisible();

    // Record timestamp before simulating badge scan
    const beforeScanTime = new Date();

    // Simulate badge scan event
    const testEmployeeId = 'EMP-12345';
    const testBadgeId = 'BADGE-67890';
    await page.evaluate(async ({ endpoint, apiKey, employeeId, badgeId }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          employeeId: employeeId,
          badgeId: badgeId,
          timestamp: new Date().toISOString(),
          location: 'Main Office - Floor 1',
          scanType: 'entry'
        })
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, employeeId: testEmployeeId, badgeId: testBadgeId });

    // Monitor real-time data feed for badge scan event
    await page.waitForSelector(`[data-testid="event-row-${testEmployeeId}"]`, { timeout: 60000 });
    const eventRow = page.locator(`[data-testid="event-row-${testEmployeeId}"]`);
    await expect(eventRow).toBeVisible();

    // Record timestamp when event appears on dashboard
    const afterDisplayTime = new Date();
    const timeDifference = (afterDisplayTime.getTime() - beforeScanTime.getTime()) / 1000;

    // Verify event appears within 1 minute
    expect(timeDifference).toBeLessThan(60);

    // Verify event data in database
    await page.click('[data-testid="database-query-menu"]');
    await page.fill('[data-testid="query-input"]', `SELECT * FROM attendance WHERE employee_id = '${testEmployeeId}' ORDER BY timestamp DESC LIMIT 1`);
    await page.click('[data-testid="execute-query-button"]');

    // Verify database record contains all required fields
    const dbResult = page.locator('[data-testid="query-result-table"]');
    await expect(dbResult).toBeVisible();
    await expect(dbResult.locator('[data-testid="field-employee-id"]')).toContainText(testEmployeeId);
    await expect(dbResult.locator('[data-testid="field-badge-id"]')).toContainText(testBadgeId);
    await expect(dbResult.locator('[data-testid="field-location"]')).toContainText('Main Office - Floor 1');
    await expect(dbResult.locator('[data-testid="field-scan-type"]')).toContainText('entry');
    await expect(dbResult.locator('[data-testid="field-system-identifier"]')).toContainText('BADGE-SYSTEM-001');
  });

  test('Verify duplicate badge scan event filtering (edge-case)', async ({ page }) => {
    // Navigate to badge scan data monitoring section
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="badge-scan-monitoring"]');
    await expect(page.locator('[data-testid="badge-scan-monitoring-section"]')).toBeVisible();

    // Query database for baseline count
    await page.click('[data-testid="database-query-menu"]');
    const testEmployeeId = 'EMP-DUPLICATE-TEST';
    await page.fill('[data-testid="query-input"]', `SELECT COUNT(*) as count FROM attendance WHERE employee_id = '${testEmployeeId}'`);
    await page.click('[data-testid="execute-query-button"]');
    const baselineCountText = await page.locator('[data-testid="count-result"]').textContent();
    const baselineCount = parseInt(baselineCountText || '0');

    // Prepare badge scan event data
    const testBadgeId = 'BADGE-DUP-001';
    const testTimestamp = new Date().toISOString();
    const testLocation = 'Main Office - Floor 2';

    const badgeScanEvent = {
      employeeId: testEmployeeId,
      badgeId: testBadgeId,
      timestamp: testTimestamp,
      location: testLocation,
      scanType: 'entry'
    };

    // Send first badge scan event
    await page.evaluate(async ({ endpoint, apiKey, event }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify(event)
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, event: badgeScanEvent });

    // Wait for first event to be stored
    await page.waitForTimeout(2000);

    // Verify first event is stored
    await page.fill('[data-testid="query-input"]', `SELECT * FROM attendance WHERE employee_id = '${testEmployeeId}' AND timestamp = '${testTimestamp}'`);
    await page.click('[data-testid="execute-query-button"]');
    await expect(page.locator('[data-testid="query-result-table"]')).toBeVisible();

    // Send identical duplicate badge scan event
    await page.evaluate(async ({ endpoint, apiKey, event }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify(event)
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, event: badgeScanEvent });

    // Wait for system to process duplicate
    await page.waitForTimeout(2000);

    // Query database to verify only one record exists
    await page.fill('[data-testid="query-input"]', `SELECT COUNT(*) as count FROM attendance WHERE employee_id = '${testEmployeeId}'`);
    await page.click('[data-testid="execute-query-button"]');
    const afterDuplicateCountText = await page.locator('[data-testid="count-result"]').textContent();
    const afterDuplicateCount = parseInt(afterDuplicateCountText || '0');

    // Verify count increased by only one
    expect(afterDuplicateCount).toBe(baselineCount + 1);

    // Send third duplicate event
    await page.evaluate(async ({ endpoint, apiKey, event }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify(event)
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, event: badgeScanEvent });

    await page.waitForTimeout(2000);

    // Navigate to admin dashboard duplicate event alerts
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="duplicate-alerts-section"]');
    await expect(page.locator('[data-testid="duplicate-alerts"]')).toBeVisible();

    // Verify duplicate event alerts show details
    const duplicateAlert = page.locator(`[data-testid="duplicate-alert-${testEmployeeId}"]`).first();
    await expect(duplicateAlert).toBeVisible();
    await expect(duplicateAlert).toContainText(testEmployeeId);
    await expect(duplicateAlert.locator('[data-testid="duplicate-count"]')).toContainText('2');

    // Send valid non-duplicate event with different timestamp
    const newTimestamp = new Date(new Date(testTimestamp).getTime() + 6000).toISOString();
    const newEvent = {
      employeeId: testEmployeeId,
      badgeId: testBadgeId,
      timestamp: newTimestamp,
      location: testLocation,
      scanType: 'exit'
    };

    await page.evaluate(async ({ endpoint, apiKey, event }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify(event)
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, event: newEvent });

    await page.waitForTimeout(2000);

    // Verify new event is stored as separate record
    await page.click('[data-testid="database-query-menu"]');
    await page.fill('[data-testid="query-input"]', `SELECT COUNT(*) as count FROM attendance WHERE employee_id = '${testEmployeeId}'`);
    await page.click('[data-testid="execute-query-button"]');
    const finalCountText = await page.locator('[data-testid="count-result"]').textContent();
    const finalCount = parseInt(finalCountText || '0');

    // Verify count increased by two total (one original + one new non-duplicate)
    expect(finalCount).toBe(baselineCount + 2);
  });

  test('Test automatic reconnection on badge scan system failure (error-case)', async ({ page }) => {
    // Navigate to badge scan system status monitoring page
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="system-status-monitoring"]');
    await expect(page.locator('[data-testid="badge-scan-status-section"]')).toBeVisible();

    // Verify last successful data transmission timestamp is recent
    const lastTransmissionTime = await page.locator('[data-testid="last-transmission-timestamp"]').textContent();
    expect(lastTransmissionTime).toBeTruthy();

    // Document current connection status
    const connectionStatus = await page.locator('[data-testid="connection-status"]').textContent();
    expect(connectionStatus).toContain('Connected');

    const uptime = await page.locator('[data-testid="system-uptime"]').textContent();
    expect(uptime).toBeTruthy();

    const eventsReceived = await page.locator('[data-testid="events-received-count"]').textContent();
    expect(eventsReceived).toBeTruthy();

    // Simulate badge scan system disconnection
    await page.evaluate(() => {
      // Trigger system disconnection via admin control
      (window as any).simulateBadgeScanDisconnection();
    });

    // Alternative: Use API to simulate disconnection
    await page.click('[data-testid="system-controls-menu"]');
    await page.click('[data-testid="simulate-disconnection-button"]');
    await page.click('[data-testid="confirm-disconnection-button"]');

    // Monitor dashboard for system detection of failure
    await page.waitForSelector('[data-testid="connection-status-disconnected"]', { timeout: 10000 });

    // Verify status changes to Disconnected with red indicator
    const disconnectedStatus = page.locator('[data-testid="connection-status-disconnected"]');
    await expect(disconnectedStatus).toBeVisible();
    await expect(disconnectedStatus).toHaveClass(/status-error|status-red|disconnected/);

    // Check for admin alert notification
    const alertNotification = page.locator('[data-testid="system-failure-alert"]');
    await expect(alertNotification).toBeVisible({ timeout: 5000 });
    await expect(alertNotification).toContainText('Badge scan system failure');

    // Verify alert details
    await page.click('[data-testid="view-alert-details"]');
    await expect(page.locator('[data-testid="alert-notification-channel"]')).toBeVisible();

    // Check system logs for failure detection entry
    await page.click('[data-testid="system-logs-menu"]');
    await page.fill('[data-testid="log-filter-input"]', 'badge scan failure');
    await page.click('[data-testid="apply-filter-button"]');
    const failureLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(failureLogEntry).toBeVisible();
    await expect(failureLogEntry).toContainText('failure detected');

    // Observe automatic reconnection attempts indicator
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="system-status-monitoring"]');
    const reconnectionIndicator = page.locator('[data-testid="reconnection-attempts-indicator"]');
    await expect(reconnectionIndicator).toBeVisible();

    // Wait for retry interval and verify reconnection attempt
    await page.waitForTimeout(30000);
    const attemptCount = await page.locator('[data-testid="reconnection-attempt-count"]').textContent();
    expect(parseInt(attemptCount || '0')).toBeGreaterThan(0);

    // Allow system to continue retry attempts for 2 minutes
    await page.waitForTimeout(120000);

    // Restore badge scan system connection
    await page.click('[data-testid="system-controls-menu"]');
    await page.click('[data-testid="restore-connection-button"]');
    await page.click('[data-testid="confirm-restore-button"]');

    // Monitor dashboard for successful automatic reconnection
    await page.waitForSelector('[data-testid="connection-status-connected"]', { timeout: 60000 });

    // Verify status changes to Connected with green indicator
    const connectedStatus = page.locator('[data-testid="connection-status-connected"]');
    await expect(connectedStatus).toBeVisible();
    await expect(connectedStatus).toHaveClass(/status-success|status-green|connected/);

    // Check for reconnection success notification
    const successNotification = page.locator('[data-testid="reconnection-success-notification"]');
    await expect(successNotification).toBeVisible();

    // Verify system logs contain reconnection success entry
    await page.click('[data-testid="system-logs-menu"]');
    await page.fill('[data-testid="log-filter-input"]', 'reconnection success');
    await page.click('[data-testid="apply-filter-button"]');
    const successLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(successLogEntry).toBeVisible();
    await expect(successLogEntry).toContainText('reconnection successful');

    // Simulate new badge scan event
    const testEmployeeId = 'EMP-RECONNECT-TEST';
    const testBadgeId = 'BADGE-RECONNECT-001';
    const beforeScanTime = new Date();

    await page.evaluate(async ({ endpoint, apiKey, employeeId, badgeId }) => {
      await fetch(`${endpoint}/badge-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          employeeId: employeeId,
          badgeId: badgeId,
          timestamp: new Date().toISOString(),
          location: 'Main Office - Floor 3',
          scanType: 'entry'
        })
      });
    }, { endpoint: badgeScanAPIEndpoint, apiKey: badgeScanAPIKey, employeeId: testEmployeeId, badgeId: testBadgeId });

    // Verify event is received and displayed within 1 minute
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="realtime-data-dashboard"]');
    await page.waitForSelector(`[data-testid="event-row-${testEmployeeId}"]`, { timeout: 60000 });
    const eventRow = page.locator(`[data-testid="event-row-${testEmployeeId}"]`);
    await expect(eventRow).toBeVisible();

    const afterDisplayTime = new Date();
    const timeDifference = (afterDisplayTime.getTime() - beforeScanTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThan(60);

    // Query database to confirm event is stored successfully
    await page.click('[data-testid="database-query-menu"]');
    await page.fill('[data-testid="query-input"]', `SELECT * FROM attendance WHERE employee_id = '${testEmployeeId}' ORDER BY timestamp DESC LIMIT 1`);
    await page.click('[data-testid="execute-query-button"]');
    const dbResult = page.locator('[data-testid="query-result-table"]');
    await expect(dbResult).toBeVisible();
    await expect(dbResult.locator('[data-testid="field-employee-id"]')).toContainText(testEmployeeId);
    await expect(dbResult.locator('[data-testid="field-badge-id"]')).toContainText(testBadgeId);

    // Review complete system logs for disconnection and reconnection cycle
    await page.click('[data-testid="system-logs-menu"]');
    await page.fill('[data-testid="log-filter-input"]', 'badge scan');
    await page.click('[data-testid="apply-filter-button"]');
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(0);

    // Verify logs contain both failure and success entries
    const allLogsText = await page.locator('[data-testid="log-entries-container"]').textContent();
    expect(allLogsText).toContain('failure detected');
    expect(allLogsText).toContain('reconnection successful');
  });
});