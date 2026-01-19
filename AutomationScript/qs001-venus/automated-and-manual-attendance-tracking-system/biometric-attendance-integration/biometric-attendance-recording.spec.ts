import { test, expect } from '@playwright/test';

test.describe('Biometric Attendance Recording', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const BIOMETRIC_DEVICE_URL = `${BASE_URL}/biometric-device`;
  const ATTENDANCE_DASHBOARD_URL = `${BASE_URL}/attendance/dashboard`;
  const VALID_EMPLOYEE_ID = 'EMP001';
  const VALID_BIOMETRIC_DATA = 'valid_fingerprint_hash_12345';
  const INVALID_BIOMETRIC_DATA = 'invalid_fingerprint_hash_99999';

  test.beforeEach(async ({ page }) => {
    // Navigate to biometric device interface
    await page.goto(BIOMETRIC_DEVICE_URL);
    await expect(page).toHaveTitle(/Biometric Authentication/);
  });

  test('Validate successful attendance recording via biometric authentication', async ({ page }) => {
    // Step 1: Employee authenticates using biometric device
    await page.click('[data-testid="biometric-scanner-activate"]');
    await expect(page.locator('[data-testid="scanner-status"]')).toHaveText('Ready to scan');

    // Simulate biometric data capture
    await page.fill('[data-testid="biometric-input"]', VALID_BIOMETRIC_DATA);
    await page.click('[data-testid="submit-biometric"]');

    // Expected Result: System validates biometric data successfully
    await expect(page.locator('[data-testid="validation-status"]')).toHaveText('Validation successful', { timeout: 5000 });

    // Step 2: System records attendance timestamp
    const timestampBefore = new Date();
    await page.waitForSelector('[data-testid="attendance-recorded"]', { timeout: 3000 });
    const timestampAfter = new Date();

    // Expected Result: Attendance recorded with accurate timestamp
    const recordedTimestamp = await page.locator('[data-testid="recorded-timestamp"]').textContent();
    expect(recordedTimestamp).toBeTruthy();

    // Verify timestamp is within acceptable range (2 seconds)
    const timeDifference = timestampAfter.getTime() - timestampBefore.getTime();
    expect(timeDifference).toBeLessThanOrEqual(2000);

    // Step 3: System displays confirmation message
    // Expected Result: Employee sees confirmation of attendance capture
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Attendance recorded successfully');
    await expect(page.locator('[data-testid="employee-name"]')).toBeVisible();

    // Verify attendance record in employee attendance dashboard
    await page.goto(ATTENDANCE_DASHBOARD_URL);
    await page.fill('[data-testid="employee-id-filter"]', VALID_EMPLOYEE_ID);
    await page.click('[data-testid="filter-submit"]');
    
    const attendanceRecord = page.locator('[data-testid="attendance-record"]').first();
    await expect(attendanceRecord).toBeVisible();
    await expect(attendanceRecord.locator('[data-testid="record-status"]')).toHaveText('Present');

    // Check system logs for the attendance event
    await page.goto(`${BASE_URL}/admin/logs`);
    await page.fill('[data-testid="log-search"]', `attendance ${VALID_EMPLOYEE_ID}`);
    await page.click('[data-testid="search-logs"]');
    
    const logEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(logEntry).toBeVisible();
    await expect(logEntry).toContainText('Attendance recorded');
    await expect(logEntry).toContainText(VALID_EMPLOYEE_ID);
  });

  test('Verify rejection of invalid biometric authentication', async ({ page }) => {
    // Step 1: Unregistered person attempts authentication
    await page.click('[data-testid="biometric-scanner-activate"]');
    await expect(page.locator('[data-testid="scanner-status"]')).toHaveText('Ready to scan');

    // Simulate invalid biometric data capture
    await page.fill('[data-testid="biometric-input"]', INVALID_BIOMETRIC_DATA);
    await page.click('[data-testid="submit-biometric"]');

    // Expected Result: System rejects authentication and prompts retry
    await expect(page.locator('[data-testid="validation-status"]')).toHaveText('Authentication failed', { timeout: 5000 });
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Biometric data not recognized');
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();

    // Verify no attendance record is created
    await page.goto(ATTENDANCE_DASHBOARD_URL);
    await page.fill('[data-testid="employee-id-filter"]', 'UNKNOWN');
    await page.click('[data-testid="filter-submit"]');
    
    const noRecordsMessage = page.locator('[data-testid="no-records-message"]');
    await expect(noRecordsMessage).toBeVisible();

    // Step 2: Employee retries authentication with valid biometric data
    await page.goto(BIOMETRIC_DEVICE_URL);
    await page.click('[data-testid="biometric-scanner-activate"]');
    await page.fill('[data-testid="biometric-input"]', VALID_BIOMETRIC_DATA);
    await page.click('[data-testid="submit-biometric"]');

    // Expected Result: System accepts and records attendance
    await expect(page.locator('[data-testid="validation-status"]')).toHaveText('Validation successful', { timeout: 5000 });
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Attendance recorded successfully');

    // Step 3: System logs invalid authentication attempt
    // Expected Result: Audit log contains rejection event
    await page.goto(`${BASE_URL}/admin/audit-logs`);
    await page.selectOption('[data-testid="log-type-filter"]', 'authentication');
    await page.fill('[data-testid="log-search"]', 'failed');
    await page.click('[data-testid="search-logs"]');

    const failedLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Authentication failed' }).first();
    await expect(failedLogEntry).toBeVisible();
    await expect(failedLogEntry).toContainText('Biometric authentication rejected');

    // Verify successful authentication is also logged
    await page.fill('[data-testid="log-search"]', VALID_EMPLOYEE_ID);
    await page.click('[data-testid="search-logs"]');
    
    const successLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Attendance recorded' }).first();
    await expect(successLogEntry).toBeVisible();
    await expect(successLogEntry).toContainText(VALID_EMPLOYEE_ID);
  });

  test('Ensure attendance timestamp accuracy', async ({ page }) => {
    // Step 1: Note the current accurate time from reference clock
    const referenceTime = new Date();
    const referenceTimeString = referenceTime.toISOString();
    const dateString = referenceTime.toISOString().split('T')[0];

    // Step 2: Employee authenticates using biometric device at the noted time
    await page.click('[data-testid="biometric-scanner-activate"]');
    await page.fill('[data-testid="biometric-input"]', VALID_BIOMETRIC_DATA);
    await page.click('[data-testid="submit-biometric"]');

    // Expected Result: System validates and records attendance
    await expect(page.locator('[data-testid="validation-status"]')).toHaveText('Validation successful', { timeout: 5000 });
    await page.waitForSelector('[data-testid="attendance-recorded"]', { timeout: 3000 });

    // Step 3: Observe the timestamp displayed on confirmation message
    const displayedTimestamp = await page.locator('[data-testid="recorded-timestamp"]').textContent();
    expect(displayedTimestamp).toBeTruthy();

    // Step 4: Access the database and query the attendance record
    await page.goto(`${BASE_URL}/admin/database-query`);
    await page.fill('[data-testid="sql-query-input"]', `SELECT * FROM attendance WHERE employee_id = '${VALID_EMPLOYEE_ID}' AND date = '${dateString}' ORDER BY timestamp DESC LIMIT 1`);
    await page.click('[data-testid="execute-query"]');

    // Expected Result: Compare database timestamp with reference authentication time
    const dbTimestampCell = page.locator('[data-testid="query-result-row"]').first().locator('[data-testid="timestamp-cell"]');
    await expect(dbTimestampCell).toBeVisible();
    const dbTimestamp = await dbTimestampCell.textContent();
    
    // Step 5: Verify timestamp accuracy within 2 seconds
    const dbTime = new Date(dbTimestamp!);
    const timeDifference = Math.abs(dbTime.getTime() - referenceTime.getTime());
    expect(timeDifference).toBeLessThanOrEqual(2000);

    // Step 6: Verify all timestamp components
    expect(dbTimestamp).toContain(dateString);
    
    // Step 7: Navigate to attendance reporting module
    await page.goto(`${BASE_URL}/reports/attendance`);
    await page.fill('[data-testid="employee-id-input"]', VALID_EMPLOYEE_ID);
    await page.fill('[data-testid="date-from"]', dateString);
    await page.fill('[data-testid="date-to"]', dateString);
    await page.click('[data-testid="generate-report"]');

    // Expected Result: Report reflects accurate attendance timestamps
    await expect(page.locator('[data-testid="report-generated"]')).toBeVisible({ timeout: 5000 });
    
    const reportTimestamp = page.locator('[data-testid="report-row"]').first().locator('[data-testid="report-timestamp"]');
    await expect(reportTimestamp).toBeVisible();
    const reportTimestampText = await reportTimestamp.textContent();

    // Verify timestamp in report matches database timestamp
    expect(reportTimestampText).toContain(dateString);

    // Step 8: Perform second authentication test at different time
    await page.goto(BIOMETRIC_DEVICE_URL);
    await page.waitForTimeout(3000); // Wait 3 seconds to ensure different timestamp
    
    const secondReferenceTime = new Date();
    await page.click('[data-testid="biometric-scanner-activate"]');
    await page.fill('[data-testid="biometric-input"]', VALID_BIOMETRIC_DATA);
    await page.click('[data-testid="submit-biometric"]');

    await expect(page.locator('[data-testid="validation-status"]')).toHaveText('Validation successful', { timeout: 5000 });
    await page.waitForSelector('[data-testid="attendance-recorded"]', { timeout: 3000 });

    const secondDisplayedTimestamp = await page.locator('[data-testid="recorded-timestamp"]').textContent();
    expect(secondDisplayedTimestamp).toBeTruthy();
    expect(secondDisplayedTimestamp).not.toBe(displayedTimestamp);

    // Verify second timestamp accuracy
    await page.goto(`${BASE_URL}/admin/database-query`);
    await page.fill('[data-testid="sql-query-input"]', `SELECT * FROM attendance WHERE employee_id = '${VALID_EMPLOYEE_ID}' AND date = '${dateString}' ORDER BY timestamp DESC LIMIT 1`);
    await page.click('[data-testid="execute-query"]');

    const secondDbTimestampCell = page.locator('[data-testid="query-result-row"]').first().locator('[data-testid="timestamp-cell"]');
    const secondDbTimestamp = await secondDbTimestampCell.textContent();
    const secondDbTime = new Date(secondDbTimestamp!);
    const secondTimeDifference = Math.abs(secondDbTime.getTime() - secondReferenceTime.getTime());
    expect(secondTimeDifference).toBeLessThanOrEqual(2000);
  });
});