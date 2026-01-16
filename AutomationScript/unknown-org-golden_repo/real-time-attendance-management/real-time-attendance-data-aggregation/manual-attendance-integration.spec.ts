import { test, expect } from '@playwright/test';

test.describe('Manual Attendance Integration - Story 12', () => {
  let apiContext;
  let authToken: string;
  const baseURL = process.env.API_BASE_URL || 'http://localhost:3000';
  const adminCredentials = {
    username: 'admin@attendance.com',
    password: 'Admin@123'
  };

  test.beforeEach(async ({ page, request }) => {
    // Authenticate and get token
    const loginResponse = await request.post(`${baseURL}/api/auth/login`, {
      data: adminCredentials
    });
    expect(loginResponse.ok()).toBeTruthy();
    const loginData = await loginResponse.json();
    authToken = loginData.token;
    apiContext = request;

    // Navigate to attendance dashboard
    await page.goto(`${baseURL}/admin/attendance`);
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful manual attendance entry submission', async ({ page, request }) => {
    const manualEntry = {
      employeeId: 'EMP001',
      date: '2024-01-15',
      checkInTime: '09:00:00',
      checkOutTime: '17:30:00',
      reason: 'Biometric system malfunction',
      enteredBy: 'admin@attendance.com'
    };

    // Step 1: Submit manual attendance entry with valid data via API
    const submitResponse = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: manualEntry
    });

    expect(submitResponse.ok()).toBeTruthy();
    const responseData = await submitResponse.json();
    expect(responseData.success).toBe(true);
    expect(responseData.entryId).toBeDefined();
    const entryId = responseData.entryId;

    // Step 2: Verify entry appears in aggregated attendance data
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Search for the employee
    await page.fill('[data-testid="employee-search-input"]', manualEntry.employeeId);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-records-table"]');

    // Verify entry is visible in attendance reports
    const attendanceRow = page.locator(`[data-testid="attendance-row-${entryId}"]`);
    await expect(attendanceRow).toBeVisible();
    await expect(attendanceRow.locator('[data-testid="employee-id"]')).toContainText(manualEntry.employeeId);
    await expect(attendanceRow.locator('[data-testid="check-in-time"]')).toContainText('09:00');
    await expect(attendanceRow.locator('[data-testid="check-out-time"]')).toContainText('17:30');
    await expect(attendanceRow.locator('[data-testid="entry-type"]')).toContainText('Manual');

    // Step 3: Check audit logs for entry details
    await page.click('[data-testid="audit-logs-tab"]');
    await page.waitForSelector('[data-testid="audit-logs-table"]');
    
    // Filter audit logs by entry ID
    await page.fill('[data-testid="audit-log-search"]', entryId);
    await page.click('[data-testid="audit-search-button"]');
    
    const auditLogEntry = page.locator(`[data-testid="audit-log-${entryId}"]`);
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(manualEntry.enteredBy);
    await expect(auditLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Manual Entry Created');
  });

  test('Verify rejection of manual entries with invalid data', async ({ page, request }) => {
    // Step 1: Submit manual attendance entry with missing employee ID
    const invalidEntry1 = {
      date: '2024-01-15',
      checkInTime: '09:00:00',
      checkOutTime: '17:30:00',
      reason: 'Test entry'
    };

    const response1 = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: invalidEntry1
    });

    expect(response1.status()).toBe(400);
    const errorData1 = await response1.json();
    expect(errorData1.success).toBe(false);
    expect(errorData1.error).toContain('employeeId');
    expect(errorData1.error.toLowerCase()).toContain('required');

    // Step 2: Submit entry with invalid date format
    const invalidEntry2 = {
      employeeId: 'EMP001',
      date: '15-01-2024',
      checkInTime: '09:00:00',
      checkOutTime: '17:30:00',
      reason: 'Test entry'
    };

    const response2 = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: invalidEntry2
    });

    expect(response2.status()).toBe(400);
    const errorData2 = await response2.json();
    expect(errorData2.success).toBe(false);
    expect(errorData2.error.toLowerCase()).toMatch(/date|format|invalid/);

    // Verify validation failure is logged
    await page.goto(`${baseURL}/admin/system-logs`);
    await page.waitForLoadState('networkidle');
    await page.selectOption('[data-testid="log-type-filter"]', 'validation_error');
    await page.click('[data-testid="apply-filter-button"]');
    
    const validationLog = page.locator('[data-testid="log-entries"]').first();
    await expect(validationLog).toContainText('validation failure');

    // Step 3: Attempt submission without authentication
    const response3 = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Content-Type': 'application/json'
      },
      data: {
        employeeId: 'EMP001',
        date: '2024-01-15',
        checkInTime: '09:00:00',
        checkOutTime: '17:30:00'
      }
    });

    expect(response3.status()).toBe(401);
    const errorData3 = await response3.json();
    expect(errorData3.success).toBe(false);
    expect(errorData3.error.toLowerCase()).toMatch(/unauthorized|authentication/);
  });

  test('Test conflict detection for duplicate manual entries', async ({ page, request }) => {
    // Create initial biometric entry
    const biometricEntry = {
      employeeId: 'EMP002',
      date: '2024-01-15',
      checkInTime: '08:45:00',
      checkOutTime: '17:15:00',
      source: 'biometric'
    };

    await request.post(`${baseURL}/api/test/create-biometric-entry`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: biometricEntry
    });

    // Step 1: Submit manual entry that conflicts with existing biometric data
    const conflictingEntry = {
      employeeId: 'EMP002',
      date: '2024-01-15',
      checkInTime: '09:00:00',
      checkOutTime: '17:30:00',
      reason: 'Correction needed',
      enteredBy: 'admin@attendance.com'
    };

    const conflictResponse = await request.post(`${baseURL}/api/manual-attendance`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: conflictingEntry
    });

    expect(conflictResponse.ok()).toBeTruthy();
    const conflictData = await conflictResponse.json();
    expect(conflictData.conflict).toBe(true);
    expect(conflictData.conflictId).toBeDefined();
    const conflictId = conflictData.conflictId;

    // Verify administrator notification
    await page.goto(`${baseURL}/admin/notifications`);
    await page.waitForLoadState('networkidle');
    
    const notification = page.locator(`[data-testid="notification-${conflictId}"]`);
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Conflict detected');
    await expect(notification).toContainText('EMP002');
    await expect(notification.locator('[data-testid="notification-type"]')).toContainText('Attendance Conflict');

    // Step 2: Administrator reviews and resolves conflict
    await notification.click();
    await page.waitForSelector('[data-testid="conflict-resolution-modal"]');
    
    // View conflict details
    const biometricRecord = page.locator('[data-testid="biometric-record"]');
    await expect(biometricRecord).toContainText('08:45');
    await expect(biometricRecord).toContainText('17:15');
    
    const manualRecord = page.locator('[data-testid="manual-record"]');
    await expect(manualRecord).toContainText('09:00');
    await expect(manualRecord).toContainText('17:30');

    // Resolve conflict by selecting manual entry
    await page.click('[data-testid="select-manual-entry-radio"]');
    await page.fill('[data-testid="resolution-notes"]', 'Manual entry is correct - biometric device malfunction');
    await page.click('[data-testid="resolve-conflict-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Conflict resolved successfully');
    
    // Verify conflict status updated
    const conflictStatusResponse = await request.get(`${baseURL}/api/conflicts/${conflictId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    expect(conflictStatusResponse.ok()).toBeTruthy();
    const statusData = await conflictStatusResponse.json();
    expect(statusData.status).toBe('resolved');
    expect(statusData.resolvedBy).toBe('admin@attendance.com');
    expect(statusData.resolution).toContain('Manual entry is correct');

    // Step 3: Verify dashboard reflects resolved attendance data
    await page.goto(`${baseURL}/admin/attendance`);
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="employee-search-input"]', 'EMP002');
    await page.fill('[data-testid="date-filter"]', '2024-01-15');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="attendance-records-table"]');

    // Verify only the resolved (manual) entry is shown
    const attendanceRecords = page.locator('[data-testid^="attendance-row-"]');
    await expect(attendanceRecords).toHaveCount(1);
    
    const resolvedRecord = attendanceRecords.first();
    await expect(resolvedRecord.locator('[data-testid="check-in-time"]')).toContainText('09:00');
    await expect(resolvedRecord.locator('[data-testid="check-out-time"]')).toContainText('17:30');
    await expect(resolvedRecord.locator('[data-testid="entry-type"]')).toContainText('Manual');
    await expect(resolvedRecord.locator('[data-testid="status"]')).toContainText('Verified');
    
    // Verify conflict indicator is removed
    await expect(resolvedRecord.locator('[data-testid="conflict-indicator"]')).not.toBeVisible();
  });
});