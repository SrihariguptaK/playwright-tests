import { test, expect } from '@playwright/test';

test.describe('Story-21: Alert and Acknowledgment Audit Logging', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';
  
  let alertId: string;
  let alertTimestamp: number;
  let acknowledgmentTimestamp: number;

  test('Verify alert and acknowledgment logging (happy-path)', async ({ page, request }) => {
    // Step 1: Create a scheduling conflict that triggers an alert
    await page.goto(`${BASE_URL}/scheduling`);
    await page.waitForLoadState('networkidle');
    
    // Login as scheduler to create conflict
    await page.getByTestId('username-input').fill('scheduler@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Create scheduling conflict
    await page.getByTestId('create-schedule-button').click();
    await page.getByTestId('resource-select').selectOption('Resource-A');
    await page.getByTestId('start-time-input').fill('2024-01-15T10:00');
    await page.getByTestId('end-time-input').fill('2024-01-15T12:00');
    await page.getByTestId('assigned-user-select').selectOption('user@example.com');
    await page.getByTestId('submit-schedule-button').click();
    
    // Create conflicting schedule
    await page.getByTestId('create-schedule-button').click();
    await page.getByTestId('resource-select').selectOption('Resource-A');
    await page.getByTestId('start-time-input').fill('2024-01-15T11:00');
    await page.getByTestId('end-time-input').fill('2024-01-15T13:00');
    await page.getByTestId('assigned-user-select').selectOption('user@example.com');
    await page.getByTestId('submit-schedule-button').click();
    
    // Wait for conflict alert to be generated
    await page.waitForSelector('[data-testid="conflict-alert-notification"]', { timeout: 5000 });
    const conflictAlert = page.getByTestId('conflict-alert-notification');
    await expect(conflictAlert).toBeVisible();
    
    // Capture alert ID and timestamp
    alertId = await conflictAlert.getAttribute('data-alert-id') || '';
    alertTimestamp = Date.now();
    
    // Step 2: Send the alert to the target user
    await page.getByTestId('send-alert-button').click();
    await expect(page.getByText('Alert sent successfully')).toBeVisible();
    
    // Step 3: Query the audit logs to verify the alert event was logged
    const alertLogResponse = await request.get(`${API_URL}/alerts/logs`, {
      params: { alertId: alertId, eventType: 'alert_sent' }
    });
    expect(alertLogResponse.ok()).toBeTruthy();
    const alertLogData = await alertLogResponse.json();
    
    // Step 4: Verify that the logged timestamp matches the actual alert send time
    expect(alertLogData.logs).toHaveLength(1);
    const alertLog = alertLogData.logs[0];
    expect(alertLog.eventType).toBe('alert_sent');
    expect(alertLog.alertId).toBe(alertId);
    expect(alertLog.recipient).toBe('user@example.com');
    const loggedTimestamp = new Date(alertLog.timestamp).getTime();
    const timeDifference = Math.abs(loggedTimestamp - alertTimestamp);
    expect(timeDifference).toBeLessThan(5000); // Within 5 seconds tolerance
    
    // Step 5: Log in as the alert recipient user
    await page.getByTestId('logout-button').click();
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('user@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 6: View the received alert
    await page.getByTestId('alerts-menu').click();
    await page.getByTestId('view-alerts-link').click();
    await expect(page.getByTestId(`alert-item-${alertId}`)).toBeVisible();
    
    // Step 7: Acknowledge the alert
    await page.getByTestId(`alert-item-${alertId}`).click();
    await page.getByTestId('acknowledge-alert-button').click();
    acknowledgmentTimestamp = Date.now();
    await expect(page.getByText('Alert acknowledged')).toBeVisible();
    
    // Step 8: Query the audit logs to verify the acknowledgment event was logged
    await page.getByTestId('logout-button').click();
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('scheduler@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    
    const ackLogResponse = await request.get(`${API_URL}/alerts/logs`, {
      params: { alertId: alertId, eventType: 'alert_acknowledged' }
    });
    expect(ackLogResponse.ok()).toBeTruthy();
    const ackLogData = await ackLogResponse.json();
    
    // Step 9: Verify acknowledgment timestamp is accurate
    expect(ackLogData.logs).toHaveLength(1);
    const ackLog = ackLogData.logs[0];
    expect(ackLog.eventType).toBe('alert_acknowledged');
    expect(ackLog.alertId).toBe(alertId);
    expect(ackLog.userId).toBe('user@example.com');
    const ackLoggedTimestamp = new Date(ackLog.timestamp).getTime();
    const ackTimeDifference = Math.abs(ackLoggedTimestamp - acknowledgmentTimestamp);
    expect(ackTimeDifference).toBeLessThan(5000); // Within 5 seconds tolerance
    
    // Step 10: Log in as an authorized user with audit access privileges
    await page.getByTestId('logout-button').click();
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('auditor@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 11: Access the audit logs through the system interface
    await page.getByTestId('audit-menu').click();
    await page.getByTestId('audit-logs-link').click();
    await expect(page.getByTestId('audit-logs-page')).toBeVisible();
    
    // Step 12: Query for the specific alert and acknowledgment log entries
    await page.getByTestId('alert-id-filter').fill(alertId);
    await page.getByTestId('apply-filter-button').click();
    
    // Step 13: Measure the response time for the audit log query
    const queryStartTime = Date.now();
    await page.waitForSelector('[data-testid="audit-log-results"]', { timeout: 3000 });
    const queryEndTime = Date.now();
    const queryResponseTime = queryEndTime - queryStartTime;
    expect(queryResponseTime).toBeLessThan(2000); // Within 2 seconds
    
    // Step 14: Verify that log entries contain all required fields
    const logEntries = page.getByTestId('audit-log-entry');
    await expect(logEntries).toHaveCount(2); // Alert sent + acknowledgment
    
    const firstEntry = logEntries.nth(0);
    await expect(firstEntry.getByTestId('event-type')).toContainText('alert_sent');
    await expect(firstEntry.getByTestId('timestamp')).toBeVisible();
    await expect(firstEntry.getByTestId('user-id')).toContainText('user@example.com');
    await expect(firstEntry.getByTestId('alert-id')).toContainText(alertId);
    await expect(firstEntry.getByTestId('action-details')).toBeVisible();
    await expect(firstEntry.getByTestId('status')).toBeVisible();
    
    const secondEntry = logEntries.nth(1);
    await expect(secondEntry.getByTestId('event-type')).toContainText('alert_acknowledged');
    await expect(secondEntry.getByTestId('timestamp')).toBeVisible();
    await expect(secondEntry.getByTestId('user-id')).toContainText('user@example.com');
    await expect(secondEntry.getByTestId('alert-id')).toContainText(alertId);
    await expect(secondEntry.getByTestId('action-details')).toBeVisible();
    await expect(secondEntry.getByTestId('status')).toBeVisible();
  });

  test('Validate audit log security (error-case)', async ({ page, request }) => {
    // Step 1: Log in as a user without audit log access privileges
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('basic-scheduler@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    await expect(page.getByTestId('dashboard-header')).toBeVisible();
    
    // Step 2: Attempt to navigate to the audit logs interface through the application menu
    const auditMenuExists = await page.getByTestId('audit-menu').count();
    expect(auditMenuExists).toBe(0); // Menu should not be visible for unauthorized users
    
    // Step 3: Attempt to directly access the audit logs URL by typing the path in browser
    await page.goto(`${BASE_URL}/audit/logs`);
    await expect(page.getByTestId('access-denied-message')).toBeVisible();
    await expect(page.getByText(/access denied|unauthorized|forbidden/i)).toBeVisible();
    
    // Step 4: Attempt to access audit logs via API endpoint without proper authorization token
    const unauthorizedResponse = await request.get(`${API_URL}/alerts/logs`, {
      headers: {}
    });
    expect(unauthorizedResponse.status()).toBe(401);
    
    // Step 5: Attempt to access audit logs via API with valid authentication but insufficient role permissions
    const token = await page.evaluate(() => localStorage.getItem('authToken'));
    const insufficientPermissionsResponse = await request.get(`${API_URL}/alerts/logs`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    expect(insufficientPermissionsResponse.status()).toBe(403);
    const errorData = await insufficientPermissionsResponse.json();
    expect(errorData.error).toMatch(/forbidden|insufficient permissions|access denied/i);
    
    // Step 6: Verify that the unauthorized access attempt is logged in the security audit trail
    await page.getByTestId('logout-button').click();
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('security-admin@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    
    await page.getByTestId('security-audit-menu').click();
    await page.getByTestId('security-audit-logs-link').click();
    await page.getByTestId('event-type-filter').selectOption('unauthorized_access');
    await page.getByTestId('user-filter').fill('basic-scheduler@example.com');
    await page.getByTestId('apply-filter-button').click();
    
    await expect(page.getByTestId('security-log-entry').first()).toBeVisible();
    const securityLogEntry = page.getByTestId('security-log-entry').first();
    await expect(securityLogEntry.getByTestId('event-type')).toContainText('unauthorized_access');
    await expect(securityLogEntry.getByTestId('user-id')).toContainText('basic-scheduler@example.com');
    await expect(securityLogEntry.getByTestId('resource')).toContainText('/audit/logs');
    
    // Step 7: Log in as an authorized administrator and verify audit log data is encrypted at rest
    await page.getByTestId('logout-button').click();
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId('username-input').fill('admin@example.com');
    await page.getByTestId('password-input').fill('password123');
    await page.getByTestId('login-button').click();
    
    await page.getByTestId('system-settings-menu').click();
    await page.getByTestId('database-settings-link').click();
    await page.getByTestId('audit-logs-encryption-section').click();
    
    const encryptionStatus = page.getByTestId('encryption-status');
    await expect(encryptionStatus).toContainText(/enabled|active|encrypted/i);
    await expect(page.getByTestId('encryption-algorithm')).toContainText(/AES-256|RSA/i);
    
    // Step 8: Attempt to modify an existing audit log entry through the API
    const adminToken = await page.evaluate(() => localStorage.getItem('authToken'));
    
    // Get an existing audit log entry
    const getLogsResponse = await request.get(`${API_URL}/alerts/logs`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`
      },
      params: { limit: 1 }
    });
    expect(getLogsResponse.ok()).toBeTruthy();
    const logsData = await getLogsResponse.json();
    const existingLogId = logsData.logs[0].id;
    
    // Attempt to modify the log entry
    const modifyResponse = await request.put(`${API_URL}/alerts/logs/${existingLogId}`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        eventType: 'modified_event',
        timestamp: new Date().toISOString()
      }
    });
    expect(modifyResponse.status()).toBe(403);
    const modifyError = await modifyResponse.json();
    expect(modifyError.error).toMatch(/cannot modify|immutable|read-only/i);
    
    // Step 9: Verify that audit log integrity checks are in place
    await page.goto(`${BASE_URL}/audit/logs`);
    await page.getByTestId('integrity-check-button').click();
    await page.waitForSelector('[data-testid="integrity-check-result"]', { timeout: 5000 });
    
    const integrityResult = page.getByTestId('integrity-check-result');
    await expect(integrityResult).toContainText(/verified|valid|intact/i);
    await expect(page.getByTestId('checksum-status')).toContainText(/valid|verified/i);
    await expect(page.getByTestId('tampering-detected')).toContainText(/no|false|none/i);
  });
});