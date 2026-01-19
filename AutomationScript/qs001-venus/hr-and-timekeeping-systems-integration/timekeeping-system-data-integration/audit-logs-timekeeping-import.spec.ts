import { test, expect } from '@playwright/test';

test.describe('Story-21: Audit Logs for Imported Timekeeping Data', () => {
  const AUTHORIZED_USER = {
    username: 'authorized.user@company.com',
    password: 'AuthorizedPass123!'
  };

  const UNAUTHORIZED_USER = {
    username: 'unauthorized.user@company.com',
    password: 'UnauthorizedPass123!'
  };

  const BASE_URL = process.env.BASE_URL || 'https://timekeeping-system.example.com';

  test('Verify audit logs for imported timekeeping data (happy-path)', async ({ page }) => {
    // Log into the timekeeping import system with authorized credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', AUTHORIZED_USER.username);
    await page.fill('[data-testid="password-input"]', AUTHORIZED_USER.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the timekeeping data import module
    await page.click('[data-testid="timekeeping-import-menu"]');
    await expect(page.locator('[data-testid="import-module"]')).toBeVisible();

    // Select the timekeeping data source and initiate the import process
    await page.selectOption('[data-testid="data-source-select"]', 'payroll-system');
    await page.click('[data-testid="select-import-file"]');
    await page.setInputFiles('[data-testid="file-upload-input"]', {
      name: 'timekeeping-data.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from('employee_id,date,hours\n1001,2024-01-15,8\n1002,2024-01-15,7.5')
    });
    
    const importTimestamp = new Date();
    await page.click('[data-testid="initiate-import-button"]');

    // Wait for the import process to complete
    await expect(page.locator('[data-testid="import-status"]')).toContainText('Import completed successfully', { timeout: 30000 });
    await expect(page.locator('[data-testid="import-progress"]')).toContainText('100%');

    // Navigate to the audit logs section of the system
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-section"]')).toBeVisible();

    // Search for audit logs related to the recently completed import using the import timestamp
    const searchTimestamp = importTimestamp.toISOString().split('T')[0];
    await page.fill('[data-testid="audit-log-search-input"]', searchTimestamp);
    await page.click('[data-testid="search-audit-logs-button"]');
    await page.waitForSelector('[data-testid="audit-log-entry"]');

    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();

    // Verify the audit log contains the import timestamp
    await expect(auditLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    const logTimestamp = await auditLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();

    // Verify the audit log contains the source details
    await expect(auditLogEntry.locator('[data-testid="log-source"]')).toContainText('payroll-system');

    // Verify the audit log contains the initiator information
    await expect(auditLogEntry.locator('[data-testid="log-initiator"]')).toContainText(AUTHORIZED_USER.username);

    // Verify the audit log contains data change records
    await auditLogEntry.click();
    await expect(page.locator('[data-testid="log-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="data-changes-section"]')).toBeVisible();
    const dataChanges = page.locator('[data-testid="data-change-record"]');
    await expect(dataChanges).toHaveCount(2); // 2 records imported

    // Verify the audit log contains the import status
    await expect(page.locator('[data-testid="import-status-log"]')).toContainText('completed');

    // Check that all imported records have corresponding audit log entries
    const recordCount = await page.locator('[data-testid="imported-records-count"]').textContent();
    const auditLogCount = await page.locator('[data-testid="audit-log-records-count"]').textContent();
    expect(recordCount).toBe(auditLogCount);

    // Verify the logging performance by checking the timestamp differences
    const importCompleteTime = await page.locator('[data-testid="import-complete-timestamp"]').textContent();
    const auditLogCreatedTime = await page.locator('[data-testid="audit-log-created-timestamp"]').textContent();
    
    if (importCompleteTime && auditLogCreatedTime) {
      const timeDiff = new Date(auditLogCreatedTime).getTime() - new Date(importCompleteTime).getTime();
      expect(timeDiff).toBeLessThan(10); // Less than 10ms per record requirement
    }
  });

  test('Verify access control for audit logs (error-case)', async ({ page }) => {
    // Log into the system using credentials of an unauthorized user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USER.username);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_USER.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to the audit logs section by entering the audit logs URL directly
    await page.goto(`${BASE_URL}/audit-logs`);

    // Verify the error message displayed to the user
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access audit logs');

    // Check that the user is not redirected to the audit logs interface
    await expect(page.locator('[data-testid="audit-logs-section"]')).not.toBeVisible();
    const currentUrl = page.url();
    expect(currentUrl).toContain('access-denied');

    // Attempt to access audit logs through the navigation menu if visible
    await page.goto(`${BASE_URL}/dashboard`);
    const auditLogsMenuItem = page.locator('[data-testid="audit-logs-menu"]');
    
    if (await auditLogsMenuItem.isVisible()) {
      await auditLogsMenuItem.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    } else {
      // Menu item should not be visible for unauthorized users
      await expect(auditLogsMenuItem).not.toBeVisible();
    }

    // Attempt to access audit log data through API endpoints using the unauthorized user's session token
    const cookies = await page.context().cookies();
    const sessionToken = cookies.find(cookie => cookie.name === 'session_token')?.value;

    const apiResponse = await page.request.get(`${BASE_URL}/api/audit-logs`, {
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Verify that no audit log data is exposed in the response
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Forbidden');
    expect(responseBody.data).toBeUndefined();

    // Log out the unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log in with an authorized user account
    await page.fill('[data-testid="username-input"]', AUTHORIZED_USER.username);
    await page.fill('[data-testid="password-input"]', AUTHORIZED_USER.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Verify that audit logs are accessible and complete for the authorized user
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]')).toHaveCount(1, { timeout: 5000 });
    
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="log-source"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="log-initiator"]')).toBeVisible();
  });
});