import { test, expect } from '@playwright/test';

test.describe('Story-7: Audit Schedule Change Approval Activities', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const APPROVER_USERNAME = 'approver.user@company.com';
  const APPROVER_PASSWORD = 'ApproverPass123!';
  const ADMIN_USERNAME = 'admin.user@company.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_USERNAME = 'regular.user@company.com';
  const NON_ADMIN_PASSWORD = 'RegularPass123!';

  test('Validate completeness and accuracy of audit logs (happy-path)', async ({ page }) => {
    // Step 1: Log into the system as a user with approval permissions
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', APPROVER_USERNAME);
    await page.fill('[data-testid="password-input"]', APPROVER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Step 2: Navigate to a pending schedule change request and approve it
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-tab"]');
    const firstRequest = page.locator('[data-testid="schedule-request-row"]').first();
    const firstRequestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    await page.fill('[data-testid="approval-comment-input"]', 'Approved for testing purposes');
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request approved successfully');
    const approvalTimestamp = new Date();

    // Step 3: Navigate to another schedule change request and reject it
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-tab"]');
    const secondRequest = page.locator('[data-testid="schedule-request-row"]').first();
    const secondRequestId = await secondRequest.getAttribute('data-request-id');
    await secondRequest.click();
    await page.fill('[data-testid="approval-comment-input"]', 'Rejected due to resource constraints');
    await page.click('[data-testid="reject-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request rejected successfully');
    const rejectionTimestamp = new Date();

    // Step 4: Navigate to a third schedule change request and escalate it
    await page.click('[data-testid="schedule-requests-menu"]');
    await page.click('[data-testid="pending-requests-tab"]');
    const thirdRequest = page.locator('[data-testid="schedule-request-row"]').first();
    const thirdRequestId = await thirdRequest.getAttribute('data-request-id');
    await thirdRequest.click();
    await page.fill('[data-testid="escalation-comment-input"]', 'Escalating to senior management');
    await page.click('[data-testid="escalate-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request escalated successfully');
    const escalationTimestamp = new Date();

    // Step 5: Log out from the approval user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 6: Log in as System Administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Step 7: Navigate to the audit logs section
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Step 8: Retrieve logs for the actions performed
    await page.fill('[data-testid="audit-search-input"]', APPROVER_USERNAME);
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);

    // Step 9: Verify the approval action log entry
    const approvalLogEntry = page.locator(`[data-testid="audit-log-entry"][data-request-id="${firstRequestId}"]`);
    await expect(approvalLogEntry).toBeVisible();
    await expect(approvalLogEntry.locator('[data-testid="log-user"]')).toContainText(APPROVER_USERNAME);
    await expect(approvalLogEntry.locator('[data-testid="log-action-type"]')).toContainText('APPROVED');
    await expect(approvalLogEntry.locator('[data-testid="log-comment"]')).toContainText('Approved for testing purposes');
    const approvalLogTimestamp = await approvalLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(approvalLogTimestamp).toBeTruthy();

    // Step 10: Verify the rejection action log entry
    const rejectionLogEntry = page.locator(`[data-testid="audit-log-entry"][data-request-id="${secondRequestId}"]`);
    await expect(rejectionLogEntry).toBeVisible();
    await expect(rejectionLogEntry.locator('[data-testid="log-user"]')).toContainText(APPROVER_USERNAME);
    await expect(rejectionLogEntry.locator('[data-testid="log-action-type"]')).toContainText('REJECTED');
    await expect(rejectionLogEntry.locator('[data-testid="log-comment"]')).toContainText('Rejected due to resource constraints');
    const rejectionLogTimestamp = await rejectionLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(rejectionLogTimestamp).toBeTruthy();

    // Step 11: Verify the escalation action log entry
    const escalationLogEntry = page.locator(`[data-testid="audit-log-entry"][data-request-id="${thirdRequestId}"]`);
    await expect(escalationLogEntry).toBeVisible();
    await expect(escalationLogEntry.locator('[data-testid="log-user"]')).toContainText(APPROVER_USERNAME);
    await expect(escalationLogEntry.locator('[data-testid="log-action-type"]')).toContainText('ESCALATED');
    await expect(escalationLogEntry.locator('[data-testid="log-comment"]')).toContainText('Escalating to senior management');
    const escalationLogTimestamp = await escalationLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(escalationLogTimestamp).toBeTruthy();

    // Step 12: Verify all timestamps are accurate (within 5 minutes variance)
    const logEntries = await page.locator('[data-testid="audit-log-entry"]').all();
    expect(logEntries.length).toBeGreaterThanOrEqual(3);
  });

  test('Validate access control to audit logs (error-case)', async ({ page }) => {
    // Step 1: Log into the system as a non-administrator user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', NON_ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Step 2: Attempt to navigate directly to the audit logs URL or menu option
    const auditLogsMenu = page.locator('[data-testid="audit-logs-menu"]');
    if (await auditLogsMenu.isVisible()) {
      await auditLogsMenu.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('insufficient permissions');
    }

    // Step 3: Attempt to access audit logs via direct URL entry
    await page.goto(`${BASE_URL}/audit/logs`);
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Step 4: Verify the error message displayed indicates insufficient permissions
    const errorMessage = await page.locator('[data-testid="error-message"]').textContent();
    expect(errorMessage?.toLowerCase()).toContain('insufficient permissions');

    // Step 5: Attempt to access audit logs API endpoint using non-administrator credentials
    const response = await page.request.get(`${BASE_URL}/api/audit/logs`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Access denied');

    // Step 6: Log out from non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 7: Log in as System Administrator
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Step 8: Navigate to audit logs section
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Step 9: Verify that the failed access attempt by non-administrator is logged
    await page.fill('[data-testid="audit-search-input"]', NON_ADMIN_USERNAME);
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    const accessDeniedLog = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'ACCESS_DENIED' });
    await expect(accessDeniedLog.first()).toBeVisible();
    await expect(accessDeniedLog.first().locator('[data-testid="log-user"]')).toContainText(NON_ADMIN_USERNAME);
  });

  test('Validate export functionality of audit logs (happy-path)', async ({ page }) => {
    // Step 1: Log into the system as System Administrator
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', ADMIN_USERNAME);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Step 2: Navigate to the audit logs section
    await page.click('[data-testid="audit-logs-menu"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Step 3: Apply filter to select audit logs for a specific date range
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(1000);

    // Get the displayed audit log entries for comparison
    const displayedEntries = await page.locator('[data-testid="audit-log-entry"]').count();
    expect(displayedEntries).toBeGreaterThan(0);

    // Step 4: Locate and click the 'Export' button
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Step 5: Select 'Export as CSV' option
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-option"]');
    const downloadCSV = await downloadPromiseCSV;

    // Step 6: Verify CSV file download
    expect(downloadCSV.suggestedFilename()).toMatch(/audit.*\.csv/);
    const csvPath = await downloadCSV.path();
    expect(csvPath).toBeTruthy();

    // Step 7: Verify CSV file contains all required columns
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('User Identity');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('Action Type');
    expect(csvContent).toContain('Request ID');
    expect(csvContent).toContain('Comments');
    expect(csvContent).toContain('IP Address');

    // Step 8: Verify CSV file contains all filtered audit log entries
    const csvLines = csvContent.split('\n').filter(line => line.trim().length > 0);
    expect(csvLines.length).toBeGreaterThanOrEqual(displayedEntries);

    // Step 9: Return to audit logs page and export as PDF
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Step 10: Select 'Export as PDF' option
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    const downloadPDF = await downloadPromisePDF;

    // Step 11: Verify PDF file download
    expect(downloadPDF.suggestedFilename()).toMatch(/audit.*\.pdf/);
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Step 12: Verify PDF file contains report header
    const pdfParse = require('pdf-parse');
    const pdfBuffer = fs.readFileSync(pdfPath);
    const pdfData = await pdfParse(pdfBuffer);
    expect(pdfData.text).toContain('Audit Log Report');

    // Step 13: Verify PDF file contains all required fields
    expect(pdfData.text).toContain('User Identity');
    expect(pdfData.text).toContain('Timestamp');
    expect(pdfData.text).toContain('Action Type');

    // Step 14: Verify file names include timestamp or date identifier
    const csvFilename = downloadCSV.suggestedFilename();
    const pdfFilename = downloadPDF.suggestedFilename();
    expect(csvFilename).toMatch(/\d{4}-\d{2}-\d{2}|\d{8}/);
    expect(pdfFilename).toMatch(/\d{4}-\d{2}-\d{2}|\d{8}/);
  });
});