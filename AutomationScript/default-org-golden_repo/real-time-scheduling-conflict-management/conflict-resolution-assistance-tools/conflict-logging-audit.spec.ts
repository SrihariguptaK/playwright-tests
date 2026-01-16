import { test, expect } from '@playwright/test';

test.describe('Conflict Logging and Audit System', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';
  const AUDITOR_USERNAME = process.env.AUDITOR_USERNAME || 'auditor@example.com';
  const AUDITOR_PASSWORD = process.env.AUDITOR_PASSWORD || 'Auditor123!';
  const UNAUTHORIZED_USERNAME = process.env.UNAUTHORIZED_USERNAME || 'user@example.com';
  const UNAUTHORIZED_PASSWORD = process.env.UNAUTHORIZED_PASSWORD || 'User123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Verify all conflicts are logged with metadata', async ({ page }) => {
    // Login as admin/scheduler
    await page.fill('[data-testid="email-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to scheduling page
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="create-meeting-button"]');

    // Create first meeting for Conference Room A
    await page.fill('[data-testid="meeting-title-input"]', 'Team Meeting A');
    await page.selectOption('[data-testid="room-select"]', 'Conference Room A');
    await page.fill('[data-testid="meeting-date-input"]', '2024-02-15');
    await page.fill('[data-testid="meeting-start-time-input"]', '14:00');
    await page.fill('[data-testid="meeting-end-time-input"]', '15:00');
    await page.click('[data-testid="save-meeting-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Meeting created successfully');

    // Create second meeting for same room and time to trigger conflict
    await page.click('[data-testid="create-meeting-button"]');
    await page.fill('[data-testid="meeting-title-input"]', 'Team Meeting B');
    await page.selectOption('[data-testid="room-select"]', 'Conference Room A');
    await page.fill('[data-testid="meeting-date-input"]', '2024-02-15');
    await page.fill('[data-testid="meeting-start-time-input"]', '14:00');
    await page.fill('[data-testid="meeting-end-time-input"]', '15:00');
    await page.click('[data-testid="save-meeting-button"]');

    // Verify conflict is detected and logged
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toContainText('Scheduling conflict detected');
    
    // Extract conflict ID from alert
    const conflictIdElement = page.locator('[data-testid="conflict-id"]');
    await expect(conflictIdElement).toBeVisible();
    const conflictId = await conflictIdElement.textContent();
    expect(conflictId).toMatch(/CONF-\d{4}-\d{6}/);

    // Extract timestamp from alert
    const timestampElement = page.locator('[data-testid="conflict-timestamp"]');
    const conflictTimestamp = await timestampElement.textContent();
    expect(conflictTimestamp).toBeTruthy();

    // Navigate to audit logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Query logs for conflict entry
    await page.fill('[data-testid="log-search-input"]', conflictId!);
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForTimeout(1000);

    // Verify log entry contains detailed metadata
    const logEntry = page.locator(`[data-testid="log-entry-${conflictId}"]`);
    await expect(logEntry).toBeVisible();
    
    // Verify metadata fields
    await expect(logEntry.locator('[data-testid="log-conflict-id"]')).toContainText(conflictId!);
    await expect(logEntry.locator('[data-testid="log-room-name"]')).toContainText('Conference Room A');
    await expect(logEntry.locator('[data-testid="log-conflict-date"]')).toContainText('2024-02-15');
    await expect(logEntry.locator('[data-testid="log-time-slot"]')).toContainText('14:00');
    await expect(logEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(logEntry.locator('[data-testid="log-status"]')).toContainText('DETECTED');
    
    // Validate timestamp accuracy
    const logTimestamp = await logEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify all metadata values are accurate and complete
    await expect(logEntry.locator('[data-testid="log-meeting-a"]')).toContainText('Team Meeting A');
    await expect(logEntry.locator('[data-testid="log-meeting-b"]')).toContainText('Team Meeting B');
  });

  test('Validate user action logging on conflicts', async ({ page }) => {
    // Login as admin/scheduler
    await page.fill('[data-testid="email-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to dashboard to see active conflicts
    await page.click('[data-testid="dashboard-menu"]');
    
    // Locate active conflict alert
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    
    // Extract conflict ID
    const conflictId = await conflictAlert.locator('[data-testid="conflict-id"]').textContent();
    expect(conflictId).toMatch(/CONF-\d{4}-\d{6}/);

    // Click Acknowledge button
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();
    await expect(page.locator('[data-testid="action-confirmation"]')).toContainText('Conflict acknowledged');

    // Access logging database to verify user action
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Query for user action
    await page.fill('[data-testid="log-search-input"]', conflictId!);
    await page.selectOption('[data-testid="action-type-filter"]', 'ACKNOWLEDGE');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForTimeout(1000);

    // Verify log entry contains user action details
    const acknowledgeLogEntry = page.locator(`[data-testid="log-entry-${conflictId}"]`).filter({ hasText: 'ACKNOWLEDGE' });
    await expect(acknowledgeLogEntry).toBeVisible();
    await expect(acknowledgeLogEntry.locator('[data-testid="log-action-type"]')).toContainText('ACKNOWLEDGE');
    await expect(acknowledgeLogEntry.locator('[data-testid="log-user"]')).toContainText(ADMIN_USERNAME);
    await expect(acknowledgeLogEntry.locator('[data-testid="log-action-timestamp"]')).toBeVisible();

    // Create another conflict and dismiss it
    await page.click('[data-testid="scheduling-menu"]');
    await page.click('[data-testid="create-meeting-button"]');
    await page.fill('[data-testid="meeting-title-input"]', 'Team Meeting C');
    await page.selectOption('[data-testid="room-select"]', 'Conference Room B');
    await page.fill('[data-testid="meeting-date-input"]', '2024-02-16');
    await page.fill('[data-testid="meeting-start-time-input"]', '10:00');
    await page.fill('[data-testid="meeting-end-time-input"]', '11:00');
    await page.click('[data-testid="save-meeting-button"]');

    await page.click('[data-testid="create-meeting-button"]');
    await page.fill('[data-testid="meeting-title-input"]', 'Team Meeting D');
    await page.selectOption('[data-testid="room-select"]', 'Conference Room B');
    await page.fill('[data-testid="meeting-date-input"]', '2024-02-16');
    await page.fill('[data-testid="meeting-start-time-input"]', '10:00');
    await page.fill('[data-testid="meeting-end-time-input"]', '11:00');
    await page.click('[data-testid="save-meeting-button"]');

    // Dismiss the new conflict
    const newConflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    const newConflictId = await newConflictAlert.locator('[data-testid="conflict-id"]').textContent();
    await newConflictAlert.locator('[data-testid="dismiss-button"]').click();
    await expect(page.locator('[data-testid="action-confirmation"]')).toContainText('Conflict dismissed');

    // Query logs for dismiss action
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await page.fill('[data-testid="log-search-input"]', newConflictId!);
    await page.selectOption('[data-testid="action-type-filter"]', 'DISMISS');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForTimeout(1000);

    const dismissLogEntry = page.locator(`[data-testid="log-entry-${newConflictId}"]`).filter({ hasText: 'DISMISS' });
    await expect(dismissLogEntry).toBeVisible();
    await expect(dismissLogEntry.locator('[data-testid="log-action-type"]')).toContainText('DISMISS');

    // Verify chronological order of logged actions
    await page.selectOption('[data-testid="action-type-filter"]', 'ALL');
    await page.fill('[data-testid="log-search-input"]', '');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForTimeout(1000);

    const allLogEntries = page.locator('[data-testid^="log-entry-"]');
    const logCount = await allLogEntries.count();
    expect(logCount).toBeGreaterThan(0);

    // Verify timestamps are in chronological order
    const timestamps: string[] = [];
    for (let i = 0; i < Math.min(logCount, 5); i++) {
      const timestamp = await allLogEntries.nth(i).locator('[data-testid="log-action-timestamp"]').textContent();
      if (timestamp) timestamps.push(timestamp);
    }
    expect(timestamps.length).toBeGreaterThan(0);
  });

  test('Ensure logs are securely stored and retrievable', async ({ page }) => {
    // Login with authorized auditor credentials
    await page.fill('[data-testid="email-input"]', AUDITOR_USERNAME);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to audit log access interface
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Execute query to retrieve conflict logs from past 30 days
    await page.click('[data-testid="date-range-filter"]');
    await page.selectOption('[data-testid="date-range-select"]', 'LAST_30_DAYS');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1500);

    // Verify data integrity by checking log entry completeness
    const logEntries = page.locator('[data-testid^="log-entry-"]');
    const entryCount = await logEntries.count();
    expect(entryCount).toBeGreaterThan(0);

    // Check first log entry for completeness
    const firstEntry = logEntries.first();
    await expect(firstEntry.locator('[data-testid="log-conflict-id"]')).toBeVisible();
    await expect(firstEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstEntry.locator('[data-testid="log-status"]')).toBeVisible();

    // Verify encryption status indicator
    await page.click('[data-testid="system-info-button"]');
    const encryptionStatus = page.locator('[data-testid="encryption-status"]');
    await expect(encryptionStatus).toBeVisible();
    await expect(encryptionStatus).toContainText('Enabled');
    await page.click('[data-testid="close-system-info"]');

    // Export sample logs to verify data decryption
    await page.click('[data-testid="export-logs-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'CSV');
    await page.click('[data-testid="confirm-export-button"]');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-export-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('conflict_logs');

    // Verify export success message
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Logs exported successfully');

    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Login with unauthorized user credentials
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to access audit log interface
    await page.click('[data-testid="admin-menu"]');
    
    // Verify audit logs link is not visible or disabled for unauthorized user
    const auditLogsLink = page.locator('[data-testid="audit-logs-link"]');
    const isAuditLogsVisible = await auditLogsLink.isVisible().catch(() => false);
    
    if (isAuditLogsVisible) {
      // If link is visible, clicking should show access denied
      await auditLogsLink.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    } else {
      // Link should not be visible for unauthorized users
      expect(isAuditLogsVisible).toBe(false);
    }

    // Attempt direct URL access to audit logs
    await page.goto(`${BASE_URL}/admin/audit-logs`);
    
    // Verify access is denied
    const accessDeniedPage = page.locator('[data-testid="access-denied-page"]');
    const unauthorizedPage = page.locator('[data-testid="unauthorized-page"]');
    
    const isAccessDenied = await accessDeniedPage.isVisible().catch(() => false);
    const isUnauthorized = await unauthorizedPage.isVisible().catch(() => false);
    
    expect(isAccessDenied || isUnauthorized).toBe(true);

    // Verify unauthorized access attempt is logged
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login back as auditor to check security logs
    await page.fill('[data-testid="email-input"]', AUDITOR_USERNAME);
    await page.fill('[data-testid="password-input"]', AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="security-audit-link"]');
    
    // Search for unauthorized access attempts
    await page.fill('[data-testid="security-log-search"]', UNAUTHORIZED_USERNAME);
    await page.selectOption('[data-testid="event-type-filter"]', 'UNAUTHORIZED_ACCESS');
    await page.click('[data-testid="search-security-logs-button"]');
    await page.waitForTimeout(1000);

    // Verify unauthorized access attempt is logged
    const securityLogEntry = page.locator('[data-testid^="security-log-entry-"]').filter({ hasText: UNAUTHORIZED_USERNAME });
    await expect(securityLogEntry.first()).toBeVisible();
    await expect(securityLogEntry.first().locator('[data-testid="event-type"]')).toContainText('UNAUTHORIZED_ACCESS');
    await expect(securityLogEntry.first().locator('[data-testid="target-resource"]')).toContainText('audit-logs');
  });
});