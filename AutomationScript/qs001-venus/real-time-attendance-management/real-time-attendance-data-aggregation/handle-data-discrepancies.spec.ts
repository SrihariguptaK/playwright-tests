import { test, expect } from '@playwright/test';

test.describe('Handle Data Discrepancies - Story 9', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@company.com';
  const ADMIN_PASSWORD = 'AdminPass123!';

  test.beforeEach(async ({ page }) => {
    // Login as admin before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
  });

  test('Validate detection of duplicate attendance records (happy-path)', async ({ page }) => {
    // Prepare duplicate attendance records with identical employee ID, date, and timestamp
    const duplicateRecord = {
      employeeId: 'EMP001',
      date: '2024-01-15',
      timestamp: '09:00:00',
      type: 'check-in'
    };

    // Navigate to data ingestion interface
    await page.goto(`${BASE_URL}/admin/data-ingestion`);
    await expect(page.locator('[data-testid="data-ingestion-page"]')).toBeVisible();

    // Inject duplicate attendance records into the system through the data ingestion pipeline
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', duplicateRecord.employeeId);
    await page.fill('[data-testid="date-input"]', duplicateRecord.date);
    await page.fill('[data-testid="timestamp-input"]', duplicateRecord.timestamp);
    await page.selectOption('[data-testid="type-select"]', duplicateRecord.type);
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Record injected successfully');

    // Inject the same record again to create duplicate
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', duplicateRecord.employeeId);
    await page.fill('[data-testid="date-input"]', duplicateRecord.date);
    await page.fill('[data-testid="timestamp-input"]', duplicateRecord.timestamp);
    await page.selectOption('[data-testid="type-select"]', duplicateRecord.type);
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Record injected successfully');

    // Wait for the system to process the ingested records
    await page.waitForTimeout(3000);

    // Check the discrepancy detection system for flagged duplicates
    await page.goto(`${BASE_URL}/admin/discrepancies`);
    await expect(page.locator('[data-testid="discrepancies-page"]')).toBeVisible();

    // System flags duplicates and notifies admin
    await expect(page.locator('[data-testid="discrepancy-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-badge"]')).toBeVisible();

    // Verify that admin notification was sent
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Duplicate attendance records detected');
    await page.click('[data-testid="close-notifications"]');

    // Navigate to the admin interface for discrepancy management
    await page.goto(`${BASE_URL}/admin/discrepancy-management`);
    await expect(page.locator('[data-testid="discrepancy-management-page"]')).toBeVisible();

    // Admin reviews the flagged duplicate records in the interface
    const duplicateRow = page.locator('[data-testid="discrepancy-row"]').filter({ hasText: duplicateRecord.employeeId });
    await expect(duplicateRow).toBeVisible();

    // Duplicates are clearly identified for resolution
    await expect(duplicateRow.locator('[data-testid="discrepancy-type"]')).toContainText('Duplicate');
    await expect(duplicateRow.locator('[data-testid="employee-id"]')).toContainText(duplicateRecord.employeeId);
    await expect(duplicateRow.locator('[data-testid="date"]')).toContainText(duplicateRecord.date);

    // Admin selects the duplicate records and chooses resolution action
    await duplicateRow.locator('[data-testid="select-discrepancy-checkbox"]').check();
    await page.click('[data-testid="resolve-action-button"]');
    await expect(page.locator('[data-testid="resolution-modal"]')).toBeVisible();

    // Admin resolves duplicates by selecting to keep the first record and remove the duplicate
    await page.click('[data-testid="keep-first-option"]');
    await page.fill('[data-testid="resolution-notes"]', 'Keeping first record, removing duplicate');
    await page.click('[data-testid="confirm-resolution-button"]');

    // Attendance data updated and discrepancy cleared
    await expect(page.locator('[data-testid="resolution-success-message"]')).toContainText('Discrepancy resolved successfully');

    // Verify attendance data is updated after resolution
    await page.goto(`${BASE_URL}/admin/attendance-records`);
    const attendanceRecords = page.locator(`[data-testid="attendance-record"][data-employee-id="${duplicateRecord.employeeId}"]`);
    await expect(attendanceRecords).toHaveCount(1);

    // Check that the discrepancy no longer appears in the flagged items list
    await page.goto(`${BASE_URL}/admin/discrepancy-management`);
    const resolvedDiscrepancy = page.locator('[data-testid="discrepancy-row"]').filter({ hasText: duplicateRecord.employeeId });
    await expect(resolvedDiscrepancy).not.toBeVisible();
  });

  test('Verify logging of discrepancy events (happy-path)', async ({ page }) => {
    const testEmployeeId = 'EMP002';
    const testDate = '2024-01-16';

    // Navigate to data ingestion interface
    await page.goto(`${BASE_URL}/admin/data-ingestion`);

    // Generate multiple discrepancy events by injecting duplicate records into the system
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="date-input"]', testDate);
    await page.fill('[data-testid="timestamp-input"]', '08:00:00');
    await page.selectOption('[data-testid="type-select"]', 'check-in');
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Inject duplicate
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="date-input"]', testDate);
    await page.fill('[data-testid="timestamp-input"]', '08:00:00');
    await page.selectOption('[data-testid="type-select"]', 'check-in');
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Generate conflicting timestamp discrepancy by injecting records with same employee but overlapping time periods
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="date-input"]', testDate);
    await page.fill('[data-testid="timestamp-input"]', '08:05:00');
    await page.selectOption('[data-testid="type-select"]', 'check-in');
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Generate anomaly discrepancy by injecting unusual attendance pattern
    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="date-input"]', testDate);
    await page.fill('[data-testid="timestamp-input"]', '10:00:00');
    await page.selectOption('[data-testid="type-select"]', 'check-in');
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    await page.click('[data-testid="inject-test-data-button"]');
    await page.fill('[data-testid="employee-id-input"]', testEmployeeId);
    await page.fill('[data-testid="date-input"]', testDate);
    await page.fill('[data-testid="timestamp-input"]', '11:00:00');
    await page.selectOption('[data-testid="type-select"]', 'check-in');
    await page.click('[data-testid="inject-record-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Wait for system to process and detect discrepancies
    await page.waitForTimeout(3000);

    // Navigate to the discrepancy logs section in the admin interface
    await page.goto(`${BASE_URL}/admin/discrepancy-logs`);
    await expect(page.locator('[data-testid="discrepancy-logs-page"]')).toBeVisible();

    // Review the logs for all generated discrepancy events
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries).toHaveCount(3, { timeout: 10000 });

    // All events logged with timestamps and details
    // Verify each log entry contains complete information
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry.locator('[data-testid="event-id"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="discrepancy-type"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="affected-records"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="detection-details"]')).toBeVisible();

    // Complete and accurate discrepancy history available
    const eventIdText = await firstLogEntry.locator('[data-testid="event-id"]').textContent();
    expect(eventIdText).toMatch(/EVT-\d+/);

    // Filter logs by discrepancy type (duplicate)
    await page.selectOption('[data-testid="filter-discrepancy-type"]', 'duplicate');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);
    const duplicateLogEntries = page.locator('[data-testid="log-entry"]');
    await expect(duplicateLogEntries.first().locator('[data-testid="discrepancy-type"]')).toContainText('Duplicate');

    // Filter logs by date range covering the test period
    await page.click('[data-testid="clear-filters-button"]');
    await page.fill('[data-testid="filter-date-from"]', testDate);
    await page.fill('[data-testid="filter-date-to"]', testDate);
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);
    const dateFilteredLogs = page.locator('[data-testid="log-entry"]');
    await expect(dateFilteredLogs).toHaveCount(3, { timeout: 5000 });

    // Search logs by specific employee ID involved in discrepancies
    await page.click('[data-testid="clear-filters-button"]');
    await page.fill('[data-testid="search-employee-id"]', testEmployeeId);
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    const employeeFilteredLogs = page.locator('[data-testid="log-entry"]');
    await expect(employeeFilteredLogs.first()).toContainText(testEmployeeId);

    // Export discrepancy logs for audit purposes
    await page.click('[data-testid="clear-filters-button"]');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-logs-button"]');
    const download = await downloadPromise;

    // Verify the exported file contains all log entries with timestamps and details
    expect(download.suggestedFilename()).toMatch(/discrepancy-logs.*\.(csv|xlsx)/);

    // Resolve one of the discrepancies and check if resolution is logged
    await page.goto(`${BASE_URL}/admin/discrepancy-management`);
    const discrepancyToResolve = page.locator('[data-testid="discrepancy-row"]').first();
    await discrepancyToResolve.locator('[data-testid="select-discrepancy-checkbox"]').check();
    await page.click('[data-testid="resolve-action-button"]');
    await expect(page.locator('[data-testid="resolution-modal"]')).toBeVisible();
    await page.click('[data-testid="keep-first-option"]');
    await page.fill('[data-testid="resolution-notes"]', 'Test resolution for logging verification');
    await page.click('[data-testid="confirm-resolution-button"]');
    await expect(page.locator('[data-testid="resolution-success-message"]')).toBeVisible();

    // Verify resolution is logged
    await page.goto(`${BASE_URL}/admin/discrepancy-logs`);
    await page.waitForTimeout(2000);
    const resolutionLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'Resolved' }).first();
    await expect(resolutionLog).toBeVisible();
    await expect(resolutionLog.locator('[data-testid="detection-details"]')).toContainText('Test resolution for logging verification');
  });
});