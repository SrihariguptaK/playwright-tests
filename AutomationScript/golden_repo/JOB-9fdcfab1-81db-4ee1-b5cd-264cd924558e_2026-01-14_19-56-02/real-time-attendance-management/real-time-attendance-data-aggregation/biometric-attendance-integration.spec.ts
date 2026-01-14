import { test, expect } from '@playwright/test';

test.describe('Biometric Attendance Integration', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Navigate to attendance management dashboard
    await page.goto(`${BASE_URL}/attendance/dashboard`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful biometric data capture and storage', async ({ page, request }) => {
    // Step 1: Simulate biometric device sending valid attendance event
    const biometricEventData = {
      employeeId: 'EMP001',
      deviceId: 'BIO-DEVICE-001',
      timestamp: new Date().toISOString(),
      eventType: 'check-in',
      biometricData: 'encrypted_fingerprint_hash_12345',
      deviceLocation: 'Main Entrance'
    };

    const eventTimestamp = new Date(biometricEventData.timestamp);

    // Send biometric event via API
    const response = await request.post(`${API_URL}/attendance/biometric`, {
      data: biometricEventData,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      }
    });

    // Expected Result: System receives and stores attendance record
    expect(response.status()).toBe(201);
    const responseBody = await response.json();
    expect(responseBody.success).toBe(true);
    expect(responseBody.data.employeeId).toBe(biometricEventData.employeeId);
    expect(responseBody.data.timestamp).toBeTruthy();

    // Step 2: Verify attendance record in database via UI
    await page.goto(`${BASE_URL}/attendance/records`);
    await page.waitForLoadState('networkidle');

    // Search for the attendance record
    await page.fill('[data-testid="employee-search-input"]', biometricEventData.employeeId);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-record-row"]');

    // Expected Result: Record matches biometric event data accurately
    const recordRow = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(recordRow.locator('[data-testid="employee-id"]')).toContainText(biometricEventData.employeeId);
    await expect(recordRow.locator('[data-testid="event-type"]')).toContainText('check-in');
    await expect(recordRow.locator('[data-testid="device-id"]')).toContainText(biometricEventData.deviceId);

    // Verify data capture latency (should be under 1 minute)
    const recordTimestampText = await recordRow.locator('[data-testid="timestamp"]').textContent();
    const recordTimestamp = new Date(recordTimestampText || '');
    const latencyMs = recordTimestamp.getTime() - eventTimestamp.getTime();
    expect(latencyMs).toBeLessThan(60000); // Less than 1 minute

    // Step 3: Check system logs for errors
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.waitForLoadState('networkidle');

    // Filter logs for biometric events
    await page.selectOption('[data-testid="log-category-filter"]', 'biometric');
    await page.fill('[data-testid="log-search-input"]', biometricEventData.deviceId);
    await page.click('[data-testid="filter-logs-button"]');
    await page.waitForTimeout(1000);

    // Expected Result: No errors logged
    const errorLogs = page.locator('[data-testid="log-entry"][data-level="error"]');
    await expect(errorLogs).toHaveCount(0);

    // Verify success log exists
    const successLog = page.locator('[data-testid="log-entry"]').filter({ hasText: biometricEventData.employeeId }).first();
    await expect(successLog).toBeVisible();
    await expect(successLog.locator('[data-testid="log-level"]')).toContainText('info');
  });

  test('Verify rejection of duplicate biometric attendance events', async ({ page, request }) => {
    // Setup: Create initial attendance event
    const originalEventData = {
      employeeId: 'EMP002',
      deviceId: 'BIO-DEVICE-002',
      timestamp: new Date().toISOString(),
      eventType: 'check-in',
      biometricData: 'encrypted_fingerprint_hash_67890',
      deviceLocation: 'Side Entrance'
    };

    // Send original event
    const originalResponse = await request.post(`${API_URL}/attendance/biometric`, {
      data: originalEventData,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      }
    });
    expect(originalResponse.status()).toBe(201);

    // Wait for processing
    await page.waitForTimeout(2000);

    // Step 1: Send duplicate attendance event
    const duplicateResponse = await request.post(`${API_URL}/attendance/biometric`, {
      data: originalEventData,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      }
    });

    // Expected Result: System rejects duplicate and logs warning
    expect(duplicateResponse.status()).toBe(409); // Conflict status
    const duplicateResponseBody = await duplicateResponse.json();
    expect(duplicateResponseBody.success).toBe(false);
    expect(duplicateResponseBody.message).toContain('duplicate');

    // Step 2: Check database for duplicate records via UI
    await page.goto(`${BASE_URL}/attendance/records`);
    await page.waitForLoadState('networkidle');

    // Search for attendance records
    await page.fill('[data-testid="employee-search-input"]', originalEventData.employeeId);
    await page.fill('[data-testid="timestamp-filter"]', originalEventData.timestamp.split('T')[0]);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-record-row"]');

    // Expected Result: No duplicate records found
    const recordRows = page.locator('[data-testid="attendance-record-row"]');
    const recordCount = await recordRows.count();
    expect(recordCount).toBe(1); // Only one record should exist

    // Verify the original record remains unchanged
    const singleRecord = recordRows.first();
    await expect(singleRecord.locator('[data-testid="employee-id"]')).toContainText(originalEventData.employeeId);
    await expect(singleRecord.locator('[data-testid="event-type"]')).toContainText('check-in');

    // Check audit trail for duplicate rejection
    await page.goto(`${BASE_URL}/admin/audit-trail`);
    await page.waitForLoadState('networkidle');

    await page.fill('[data-testid="audit-search-input"]', originalEventData.employeeId);
    await page.selectOption('[data-testid="audit-action-filter"]', 'duplicate_rejected');
    await page.click('[data-testid="search-audit-button"]');
    await page.waitForTimeout(1000);

    // Verify duplicate rejection is recorded
    const auditEntry = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'duplicate' }).first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText(originalEventData.employeeId);
  });

  test('Test system behavior on biometric device connectivity loss', async ({ page, request }) => {
    const deviceId = 'BIO-DEVICE-003';
    const employeeId = 'EMP003';

    // Navigate to device management page
    await page.goto(`${BASE_URL}/admin/devices`);
    await page.waitForLoadState('networkidle');

    // Step 1: Simulate device offline scenario
    await page.fill('[data-testid="device-search-input"]', deviceId);
    await page.click('[data-testid="search-device-button"]');
    await page.waitForSelector(`[data-testid="device-row-${deviceId}"]`);

    // Simulate disconnection via admin panel
    await page.click(`[data-testid="device-row-${deviceId}"] [data-testid="simulate-disconnect-button"]`);
    await page.waitForSelector('[data-testid="disconnect-confirmation-dialog"]');
    await page.click('[data-testid="confirm-disconnect-button"]');

    // Wait for system to detect disconnection
    await page.waitForTimeout(3000);

    // Expected Result: System logs connectivity error
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.waitForLoadState('networkidle');

    await page.selectOption('[data-testid="log-category-filter"]', 'device_connectivity');
    await page.fill('[data-testid="log-search-input"]', deviceId);
    await page.click('[data-testid="filter-logs-button"]');
    await page.waitForTimeout(1000);

    // Verify connectivity error is logged
    const errorLog = page.locator('[data-testid="log-entry"][data-level="error"]').filter({ hasText: deviceId }).first();
    await expect(errorLog).toBeVisible();
    await expect(errorLog).toContainText('connectivity');
    await expect(errorLog).toContainText(deviceId);

    // Verify timestamp is present
    const logTimestamp = await errorLog.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();

    // Expected Result: Admin notification is sent
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.waitForLoadState('networkidle');

    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: deviceId }).first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('connectivity loss');
    await expect(notification.locator('[data-testid="notification-severity"]')).toContainText('error');

    // Verify system continues to operate
    await page.goto(`${BASE_URL}/attendance/dashboard`);
    await expect(page.locator('[data-testid="dashboard-status"]')).toContainText('operational');

    // Step 2: Resume device connectivity
    await page.goto(`${BASE_URL}/admin/devices`);
    await page.waitForLoadState('networkidle');

    await page.fill('[data-testid="device-search-input"]', deviceId);
    await page.click('[data-testid="search-device-button"]');
    await page.waitForSelector(`[data-testid="device-row-${deviceId}"]`);

    // Reconnect device
    await page.click(`[data-testid="device-row-${deviceId}"] [data-testid="simulate-reconnect-button"]`);
    await page.waitForSelector('[data-testid="reconnect-confirmation-dialog"]');
    await page.click('[data-testid="confirm-reconnect-button"]');

    // Wait for reconnection
    await page.waitForTimeout(3000);

    // Send valid attendance event from reconnected device
    const attendanceEventData = {
      employeeId: employeeId,
      deviceId: deviceId,
      timestamp: new Date().toISOString(),
      eventType: 'check-in',
      biometricData: 'encrypted_fingerprint_hash_reconnect_test',
      deviceLocation: 'Test Location'
    };

    const eventResponse = await request.post(`${API_URL}/attendance/biometric`, {
      data: attendanceEventData,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      }
    });

    // Expected Result: System processes event successfully
    expect(eventResponse.status()).toBe(201);
    const eventResponseBody = await eventResponse.json();
    expect(eventResponseBody.success).toBe(true);

    // Verify successful reconnection is logged
    await page.goto(`${BASE_URL}/admin/system-logs`);
    await page.waitForLoadState('networkidle');

    await page.selectOption('[data-testid="log-category-filter"]', 'device_connectivity');
    await page.fill('[data-testid="log-search-input"]', deviceId);
    await page.click('[data-testid="filter-logs-button"]');
    await page.waitForTimeout(1000);

    const reconnectionLog = page.locator('[data-testid="log-entry"][data-level="info"]').filter({ hasText: 'reconnection' }).filter({ hasText: deviceId }).first();
    await expect(reconnectionLog).toBeVisible();

    // Verify event processing is logged
    const eventProcessingLog = page.locator('[data-testid="log-entry"]').filter({ hasText: employeeId }).filter({ hasText: deviceId }).first();
    await expect(eventProcessingLog).toBeVisible();

    // Check administrator receives reconnection notification
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.waitForLoadState('networkidle');

    const reconnectionNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: deviceId }).filter({ hasText: 'reconnected' }).first();
    await expect(reconnectionNotification).toBeVisible();
    await expect(reconnectionNotification.locator('[data-testid="notification-severity"]')).toContainText('success');
  });
});