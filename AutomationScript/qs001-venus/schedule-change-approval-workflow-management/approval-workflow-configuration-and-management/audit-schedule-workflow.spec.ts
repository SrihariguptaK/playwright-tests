import { test, expect } from '@playwright/test';

test.describe('Audit Schedule Change Approval Workflow Activities', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AdminPass123!';
  const UNAUTHORIZED_USERNAME = process.env.UNAUTHORIZED_USERNAME || 'user@example.com';
  const UNAUTHORIZED_PASSWORD = process.env.UNAUTHORIZED_PASSWORD || 'UserPass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Verify logging of schedule change workflow activities (happy-path)', async ({ page }) => {
    // Login as authorized user
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the schedule change request submission page
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.click('[data-testid="new-request-button"]');
    await expect(page.locator('[data-testid="schedule-change-form"]')).toBeVisible();

    // Submit a new schedule change request with all required details
    const scheduleId = `SCH-${Date.now()}`;
    const changeDescription = 'Update shift timing from 9AM-5PM to 10AM-6PM';
    const changeReason = 'Employee request for flexible hours';
    
    await page.fill('[data-testid="schedule-id-input"]', scheduleId);
    await page.fill('[data-testid="change-description-input"]', changeDescription);
    await page.fill('[data-testid="change-reason-input"]', changeReason);
    await page.click('[data-testid="submit-request-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule change request submitted successfully');
    const requestId = await page.locator('[data-testid="request-id"]').textContent();

    // Navigate to the approval workflow and approve the submitted schedule change request
    await page.click('[data-testid="approval-workflow-menu"]');
    await page.fill('[data-testid="search-request-input"]', requestId || '');
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="request-row-${requestId}"]`);
    await page.click('[data-testid="approve-button"]');
    await page.fill('[data-testid="approval-comments-input"]', 'Approved based on valid business justification');
    await page.click('[data-testid="confirm-approval-button"]');
    
    await expect(page.locator('[data-testid="approval-success-message"]')).toContainText('Schedule change request approved');

    // Navigate to the audit logs portal via secure access point
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-menu-item"]');
    await expect(page.locator('[data-testid="audit-logs-portal"]')).toBeVisible();

    // Query audit logs without any filters to view all recent activities
    await page.click('[data-testid="refresh-logs-button"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    // Verify that the schedule change request submission log entry contains required details
    const submissionLogRow = page.locator(`[data-testid="audit-log-row"]`).filter({ hasText: 'submission' }).filter({ hasText: requestId || '' }).first();
    await expect(submissionLogRow).toBeVisible();
    await expect(submissionLogRow.locator('[data-testid="log-user-id"]')).toContainText(ADMIN_USERNAME);
    await expect(submissionLogRow.locator('[data-testid="log-timestamp"]')).not.toBeEmpty();
    await expect(submissionLogRow.locator('[data-testid="log-action-type"]')).toContainText('submission');
    await expect(submissionLogRow.locator('[data-testid="log-request-id"]')).toContainText(requestId || '');
    await expect(submissionLogRow.locator('[data-testid="log-details"]')).toContainText(changeDescription);

    // Verify that the schedule change approval log entry contains required details
    const approvalLogRow = page.locator(`[data-testid="audit-log-row"]`).filter({ hasText: 'approval' }).filter({ hasText: requestId || '' }).first();
    await expect(approvalLogRow).toBeVisible();
    await expect(approvalLogRow.locator('[data-testid="log-user-id"]')).toContainText(ADMIN_USERNAME);
    await expect(approvalLogRow.locator('[data-testid="log-timestamp"]')).not.toBeEmpty();
    await expect(approvalLogRow.locator('[data-testid="log-action-type"]')).toContainText('approval');
    await expect(approvalLogRow.locator('[data-testid="log-request-id"]')).toContainText(requestId || '');

    // Apply filters to audit logs: filter by user, action type, and date range
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.selectOption('[data-testid="filter-user-select"]', ADMIN_USERNAME);
    await page.selectOption('[data-testid="filter-action-type-select"]', 'submission');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="filter-date-from-input"]', today);
    await page.fill('[data-testid="filter-date-to-input"]', today);
    
    const startTime = Date.now();
    await page.click('[data-testid="apply-filters-button"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    const queryTime = Date.now() - startTime;
    
    // Verify query response time is within 5 seconds
    expect(queryTime).toBeLessThan(5000);
    await expect(page.locator('[data-testid="audit-log-row"]').first()).toBeVisible();

    // Clear filters and apply new filters: filter by action type (approval) and date range
    await page.click('[data-testid="clear-filters-button"]');
    await page.selectOption('[data-testid="filter-action-type-select"]', 'approval');
    await page.fill('[data-testid="filter-date-from-input"]', today);
    await page.fill('[data-testid="filter-date-to-input"]', today);
    
    const startTime2 = Date.now();
    await page.click('[data-testid="apply-filters-button"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    const queryTime2 = Date.now() - startTime2;
    
    // Measure and record the query response time for the filtered results
    expect(queryTime2).toBeLessThan(5000);

    // Select the export option and choose CSV format for audit logs
    await page.click('[data-testid="export-logs-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'csv');
    
    // Confirm the export and download the audit log file
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('.csv');
    const csvPath = await download.path();
    expect(csvPath).toBeTruthy();

    // Open the exported CSV file and verify its contents
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('User ID');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('Action Type');
    expect(csvContent).toContain('Request ID');
    expect(csvContent).toContain(ADMIN_USERNAME);

    // Select the export option again and choose JSON format for audit logs
    await page.click('[data-testid="export-logs-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'json');
    
    // Confirm the export and download the audit log file in JSON format
    const downloadPromise2 = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download2 = await downloadPromise2;
    
    expect(download2.suggestedFilename()).toContain('.json');
    const jsonPath = await download2.path();
    expect(jsonPath).toBeTruthy();
    
    const jsonContent = fs.readFileSync(jsonPath, 'utf-8');
    const jsonData = JSON.parse(jsonContent);
    expect(Array.isArray(jsonData)).toBeTruthy();
    expect(jsonData.length).toBeGreaterThan(0);
    expect(jsonData[0]).toHaveProperty('userId');
    expect(jsonData[0]).toHaveProperty('timestamp');
    expect(jsonData[0]).toHaveProperty('actionType');
  });

  test('Ensure audit log access is restricted (error-case)', async ({ page }) => {
    // Log out from any existing administrator session
    await page.goto(`${BASE_URL}/logout`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log in with an unauthorized user account
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to the audit logs portal URL directly
    await page.goto(`${BASE_URL}/admin/audit-logs`);
    
    // Verify access denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Check if audit logs menu option is visible in the navigation menu
    await page.goto(`${BASE_URL}/dashboard`);
    await page.click('[data-testid="admin-menu"]').catch(() => {});
    const auditLogsMenuItem = page.locator('[data-testid="audit-logs-menu-item"]');
    await expect(auditLogsMenuItem).not.toBeVisible();

    // Attempt to access audit logs via API endpoint using unauthorized user's token
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';
    
    const response = await page.request.get(`${BASE_URL}/api/audit-logs`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // Verify that access is denied via API
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error || responseBody.message).toContain('Access denied');

    // Verify that no audit log data is returned in the API response
    expect(responseBody.data || responseBody.logs).toBeUndefined();

    // Log out from the unauthorized user account
    await page.goto(`${BASE_URL}/logout`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Log in with a System Administrator account that has audit log access permissions
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the audit logs portal
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-menu-item"]');
    await expect(page.locator('[data-testid="audit-logs-portal"]')).toBeVisible();

    // Verify that the previous unauthorized access attempts are logged
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.selectOption('[data-testid="filter-action-type-select"]', 'unauthorized_access_attempt');
    await page.selectOption('[data-testid="filter-user-select"]', UNAUTHORIZED_USERNAME);
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="filter-date-from-input"]', today);
    await page.fill('[data-testid="filter-date-to-input"]', today);
    await page.click('[data-testid="apply-filters-button"]');
    
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    const unauthorizedAccessLog = page.locator('[data-testid="audit-log-row"]').filter({ hasText: UNAUTHORIZED_USERNAME }).filter({ hasText: 'unauthorized_access_attempt' }).first();
    await expect(unauthorizedAccessLog).toBeVisible();
    await expect(unauthorizedAccessLog.locator('[data-testid="log-details"]')).toContainText('audit-logs');
  });
});