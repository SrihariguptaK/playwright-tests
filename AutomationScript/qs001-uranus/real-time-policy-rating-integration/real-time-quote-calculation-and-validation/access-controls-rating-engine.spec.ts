import { test, expect } from '@playwright/test';

interface AuthResponse {
  token: string;
  userId: string;
  role: string;
}

interface ConfigResponse {
  engine_version?: string;
  rate_tables?: any[];
  calculation_rules?: any[];
  error?: string;
  message?: string;
}

interface LogEntry {
  timestamp: string;
  userId: string;
  endpoint: string;
  method: string;
  statusCode: number;
  result: string;
}

describe('Access Controls for Rating Engine Integration - Story 20', () => {
  let baseURL: string;
  let adminToken: string;
  let readonlyToken: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'https://rating-engine-integration.example.com';
    await page.goto(baseURL);
  });

  test('Verify role-based access enforcement (happy-path)', async ({ page, request }) => {
    // Step 1: Authenticate as user 'admin_user01' with 'Integration_Admin' role and obtain authentication token
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'admin_user01');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-profile"]')).toContainText('admin_user01');
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Integration_Admin');
    
    // Extract admin token from session storage or API response
    adminToken = await page.evaluate(() => localStorage.getItem('authToken') || '');
    expect(adminToken).toBeTruthy();

    // Step 2: Send GET request to protected API endpoint '/api/rating-engine/config' using the authorized user's authentication token
    const adminResponse = await request.get(`${baseURL}/api/rating-engine/config`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });

    expect(adminResponse.status()).toBe(200);
    const adminData: ConfigResponse = await adminResponse.json();

    // Step 3: Verify the response payload contains expected configuration data fields
    expect(adminData).toHaveProperty('engine_version');
    expect(adminData).toHaveProperty('rate_tables');
    expect(adminData).toHaveProperty('calculation_rules');
    expect(adminData.engine_version).toBeTruthy();
    expect(Array.isArray(adminData.rate_tables)).toBe(true);
    expect(Array.isArray(adminData.calculation_rules)).toBe(true);

    // Step 4: Authenticate as user 'readonly_user01' with 'Read_Only' role and obtain authentication token
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    await page.fill('[data-testid="username-input"]', 'readonly_user01');
    await page.fill('[data-testid="password-input"]', 'ReadOnlyPass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="user-profile"]')).toContainText('readonly_user01');
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Read_Only');
    
    readonlyToken = await page.evaluate(() => localStorage.getItem('authToken') || '');
    expect(readonlyToken).toBeTruthy();

    // Step 5: Send GET request to the same protected API endpoint using the unauthorized user's authentication token
    const readonlyResponse = await request.get(`${baseURL}/api/rating-engine/config`, {
      headers: {
        'Authorization': `Bearer ${readonlyToken}`,
        'Content-Type': 'application/json'
      }
    });

    expect(readonlyResponse.status()).toBe(403);
    const readonlyData: ConfigResponse = await readonlyResponse.json();

    // Step 6: Verify that no configuration data is returned in the error response payload
    expect(readonlyData).not.toHaveProperty('engine_version');
    expect(readonlyData).not.toHaveProperty('rate_tables');
    expect(readonlyData).not.toHaveProperty('calculation_rules');
    expect(readonlyData.error || readonlyData.message).toContain('Access denied');

    // Step 7: Access the system access logs dashboard and filter logs for the API endpoint
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', 'admin_user01');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="navigation-menu"]');
    await page.click('[data-testid="access-logs-link"]');
    await expect(page.locator('[data-testid="access-logs-dashboard"]')).toBeVisible();

    await page.fill('[data-testid="endpoint-filter"]', '/api/rating-engine/config');
    await page.click('[data-testid="time-range-dropdown"]');
    await page.click('[data-testid="last-10-minutes-option"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForSelector('[data-testid="log-entries-table"]');

    // Step 8: Verify the log entry for the authorized user's successful access attempt
    const adminLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'admin_user01' }).filter({ hasText: '/api/rating-engine/config' });
    await expect(adminLogEntry).toBeVisible();
    await expect(adminLogEntry.locator('[data-testid="log-status"]')).toContainText('200');
    await expect(adminLogEntry.locator('[data-testid="log-result"]')).toContainText('Access granted');
    await expect(adminLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();

    // Step 9: Verify the log entry for the unauthorized user's denied access attempt
    const readonlyLogEntry = page.locator('[data-testid="log-entry"]').filter({ hasText: 'readonly_user01' }).filter({ hasText: '/api/rating-engine/config' });
    await expect(readonlyLogEntry).toBeVisible();
    await expect(readonlyLogEntry.locator('[data-testid="log-status"]')).toContainText('403');
    await expect(readonlyLogEntry.locator('[data-testid="log-result"]')).toContainText('Access denied');
    await expect(readonlyLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();

    // Step 10: Export the access log entries for both attempts in CSV format
    await page.click('[data-testid="export-logs-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('.csv');
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
  });

  test('Validate access review reporting (happy-path)', async ({ page }) => {
    // Step 1: Log in to the system administration portal with System Administrator credentials
    await page.goto(`${baseURL}/admin`);
    await page.fill('[data-testid="admin-username-input"]', 'sysadmin');
    await page.fill('[data-testid="admin-password-input"]', 'SysAdminPass123!');
    await page.click('[data-testid="admin-login-button"]');
    
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="admin-user-profile"]')).toContainText('System Administrator');

    // Step 2: Navigate to 'Access Review Reports' section and select 'Generate Monthly Access Report' option
    await page.click('[data-testid="admin-navigation-menu"]');
    await page.click('[data-testid="access-review-reports-link"]');
    await expect(page.locator('[data-testid="access-review-reports-section"]')).toBeVisible();
    
    await page.click('[data-testid="generate-monthly-access-report-button"]');
    await expect(page.locator('[data-testid="report-generation-modal"]')).toBeVisible();

    // Step 3: Set the report parameters
    await page.click('[data-testid="date-range-dropdown"]');
    await page.click('[data-testid="last-month-option"]');
    
    const dateRangeValue = await page.locator('[data-testid="date-range-display"]').textContent();
    expect(dateRangeValue).toMatch(/\d{4}-\d{2}-\d{2}/);
    
    await page.check('[data-testid="include-all-users-checkbox"]');
    await expect(page.locator('[data-testid="include-all-users-checkbox"]')).toBeChecked();
    
    await page.check('[data-testid="include-all-endpoints-checkbox"]');
    await expect(page.locator('[data-testid="include-all-endpoints-checkbox"]')).toBeChecked();
    
    await page.check('[data-testid="include-all-access-types-checkbox"]');
    await expect(page.locator('[data-testid="include-all-access-types-checkbox"]')).toBeChecked();
    
    await page.click('[data-testid="report-format-dropdown"]');
    await page.click('[data-testid="pdf-with-summary-option"]');
    await expect(page.locator('[data-testid="report-format-display"]')).toContainText('PDF with Summary');

    // Step 4: Click 'Generate Report' button and wait for report processing
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-processing-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-processing-indicator"]')).toContainText('Generating report');
    
    await page.waitForSelector('[data-testid="report-ready-notification"]', { timeout: 60000 });
    await expect(page.locator('[data-testid="report-ready-notification"]')).toContainText('Report generated successfully');

    // Step 5: Download and open the generated access report PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-report-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('Access_Report');
    expect(download.suggestedFilename()).toContain('.pdf');
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();

    // Step 6: Review the Executive Summary section of the report
    await page.click('[data-testid="view-report-online-button"]');
    await expect(page.locator('[data-testid="report-viewer"]')).toBeVisible();
    
    const executiveSummary = page.locator('[data-testid="executive-summary-section"]');
    await expect(executiveSummary).toBeVisible();
    await expect(executiveSummary.locator('[data-testid="total-access-events"]')).toBeVisible();
    await expect(executiveSummary.locator('[data-testid="unique-users-count"]')).toBeVisible();
    await expect(executiveSummary.locator('[data-testid="successful-access-count"]')).toBeVisible();
    await expect(executiveSummary.locator('[data-testid="denied-access-count"]')).toBeVisible();

    // Step 7: Review the Detailed Access Events section
    await page.click('[data-testid="detailed-access-events-tab"]');
    const detailedEvents = page.locator('[data-testid="detailed-access-events-section"]');
    await expect(detailedEvents).toBeVisible();
    
    const eventsTable = detailedEvents.locator('[data-testid="access-events-table"]');
    await expect(eventsTable).toBeVisible();
    await expect(eventsTable.locator('thead')).toContainText('Timestamp');
    await expect(eventsTable.locator('thead')).toContainText('User');
    await expect(eventsTable.locator('thead')).toContainText('Endpoint');
    await expect(eventsTable.locator('thead')).toContainText('Method');
    await expect(eventsTable.locator('thead')).toContainText('Status');
    await expect(eventsTable.locator('thead')).toContainText('Result');
    
    const tableRows = eventsTable.locator('tbody tr');
    await expect(tableRows.first()).toBeVisible();

    // Step 8: Navigate to the 'Anomalies and Security Alerts' section
    await page.click('[data-testid="anomalies-security-alerts-tab"]');
    const anomaliesSection = page.locator('[data-testid="anomalies-security-alerts-section"]');
    await expect(anomaliesSection).toBeVisible();

    // Step 9: Review flagged anomaly
    const anomalyEntry = anomaliesSection.locator('[data-testid="anomaly-entry"]').filter({ hasText: 'readonly_user02' });
    await expect(anomalyEntry).toBeVisible();
    await expect(anomalyEntry).toContainText('attempted to access admin endpoint');
    await expect(anomalyEntry).toContainText('15 times');
    await expect(anomalyEntry).toContainText('403 errors');
    await expect(anomalyEntry).toContainText('2024-01-15');
    await expect(anomalyEntry.locator('[data-testid="anomaly-severity"]')).toContainText('High');

    // Step 10: Check the 'Compliance Summary' section
    await page.click('[data-testid="compliance-summary-tab"]');
    const complianceSection = page.locator('[data-testid="compliance-summary-section"]');
    await expect(complianceSection).toBeVisible();
    await expect(complianceSection.locator('[data-testid="rbac-compliance-status"]')).toBeVisible();
    await expect(complianceSection.locator('[data-testid="access-review-completion"]')).toBeVisible();
    await expect(complianceSection.locator('[data-testid="security-violations-count"]')).toBeVisible();

    // Step 11: Export the detailed access events data in CSV format
    await page.click('[data-testid="detailed-access-events-tab"]');
    await page.click('[data-testid="export-events-button"]');
    await page.click('[data-testid="export-to-csv-option"]');
    
    const csvDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-csv-export-button"]');
    const csvDownload = await csvDownloadPromise;
    
    expect(csvDownload.suggestedFilename()).toContain('Access_Events');
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Step 12: Verify report archival by checking the 'Report History' section
    await page.click('[data-testid="close-report-viewer-button"]');
    await page.click('[data-testid="report-history-tab"]');
    
    const reportHistory = page.locator('[data-testid="report-history-section"]');
    await expect(reportHistory).toBeVisible();
    
    const latestReport = reportHistory.locator('[data-testid="report-history-entry"]').first();
    await expect(latestReport).toBeVisible();
    await expect(latestReport.locator('[data-testid="report-type"]')).toContainText('Monthly Access Report');
    await expect(latestReport.locator('[data-testid="report-date"]')).toBeVisible();
    await expect(latestReport.locator('[data-testid="report-status"]')).toContainText('Archived');
    await expect(latestReport.locator('[data-testid="generated-by"]')).toContainText('sysadmin');
  });
});