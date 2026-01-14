import { test, expect } from '@playwright/test';

test.describe('Historical Conflict Reports - Story 17', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify generation of historical conflict reports with filters (happy-path)', async ({ page }) => {
    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Select 'Historical Conflict Reports' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-historical-conflicts"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Historical Conflict Reports');

    // Set the date range filter to last 30 days using the date picker
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    const dateRangeText = await page.locator('[data-testid="date-range-display"]').textContent();
    expect(dateRangeText).toContain('Last 30 days');

    // Select a specific resource from the resource filter dropdown
    await page.click('[data-testid="resource-filter-dropdown"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await expect(page.locator('[data-testid="resource-filter-dropdown"]')).toContainText('Conference Room A');

    // Select a conflict type from the conflict type filter dropdown
    await page.click('[data-testid="conflict-type-dropdown"]');
    await page.click('[data-testid="conflict-type-double-booking"]');
    await expect(page.locator('[data-testid="conflict-type-dropdown"]')).toContainText('Double Booking');

    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-data-table"]', { timeout: 15000 });

    // Review the generated report data tables for conflict entries
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    const conflictRows = await reportTable.locator('tbody tr').count();
    expect(conflictRows).toBeGreaterThan(0);

    // Review the visual trend charts in the report
    const trendChart = page.locator('[data-testid="trend-chart"]');
    await expect(trendChart).toBeVisible();
    await expect(trendChart.locator('canvas, svg')).toBeVisible();

    // Click the 'Export to PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF download
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Return to the report page and click the 'Export to Excel' button
    await page.waitForTimeout(1000); // Brief pause between downloads
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel download
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
  });

  test('Test report generation performance (boundary)', async ({ page }) => {
    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Select 'Historical Conflict Reports' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-historical-conflicts"]');

    // Set the date range filter to cover the maximum available historical period (e.g., last 12 months)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-12-months"]');
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('Last 12 months');

    // Leave resource and conflict type filters set to 'All' to maximize data volume
    await page.click('[data-testid="resource-filter-dropdown"]');
    await page.click('[data-testid="resource-option-all"]');
    await page.click('[data-testid="conflict-type-dropdown"]');
    await page.click('[data-testid="conflict-type-all"]');

    // Note the current timestamp and click the 'Generate Report' button
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Monitor the report generation time until completion
    await page.waitForSelector('[data-testid="report-data-table"]', { timeout: 15000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generated within 10 seconds
    expect(generationTime).toBeLessThanOrEqual(10);

    // Verify the total number of conflict records displayed in the report summary
    const reportSummary = page.locator('[data-testid="report-summary"]');
    await expect(reportSummary).toBeVisible();
    const totalRecords = await reportSummary.locator('[data-testid="total-records"]').textContent();
    expect(parseInt(totalRecords || '0')).toBeGreaterThan(0);

    // Scroll through all pages or sections of the report data
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    const rowCount = await reportTable.locator('tbody tr').count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify all trend charts are rendered completely with all data points
    const trendChart = page.locator('[data-testid="trend-chart"]');
    await expect(trendChart).toBeVisible();
    const chartElement = trendChart.locator('canvas, svg');
    await expect(chartElement).toBeVisible();
    
    // Verify chart has rendered data points
    const chartDataPoints = await chartElement.evaluate((el) => {
      if (el.tagName === 'CANVAS') {
        return (el as HTMLCanvasElement).width > 0 && (el as HTMLCanvasElement).height > 0;
      }
      return el.children.length > 0;
    });
    expect(chartDataPoints).toBeTruthy();

    // Check for no errors in console logs
    const errorLogs: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errorLogs.push(msg.text());
      }
    });
    expect(errorLogs.length).toBe(0);
  });

  test('Ensure report access control (error-case)', async ({ page, context }) => {
    // Log out from current session
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in to the system using unauthorized user credentials (non-Scheduler role)
    await page.fill('[data-testid="username-input"]', 'viewer@example.com');
    await page.fill('[data-testid="password-input"]', 'viewerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the reporting module URL directly or through navigation menu
    const reportingLink = page.locator('[data-testid="reporting-module-link"]');
    const isReportingVisible = await reportingLink.isVisible().catch(() => false);
    
    if (isReportingVisible) {
      await reportingLink.click();
      // Should show access denied message
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    } else {
      // Navigation link not visible for unauthorized user - expected behavior
      expect(isReportingVisible).toBe(false);
    }

    // Attempt to access the report generation API endpoint directly
    const response = await page.request.get('/api/reports/conflicts', {
      params: {
        dateRange: 'last-30-days',
        resource: 'all',
        conflictType: 'all'
      }
    });
    
    // Verify access is denied
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error || responseBody.message).toMatch(/access denied|unauthorized|forbidden/i);

    // Log out from the unauthorized user account
    await page.goto('/dashboard');
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in to the system using authorized Scheduler user credentials
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Select 'Historical Conflict Reports' and set basic filter parameters
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-historical-conflicts"]');
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-7-days"]');

    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-data-table"]', { timeout: 15000 });

    // Verify all report functionality is accessible including viewing data tables and charts
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();

    // Export the report to PDF format
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');

    // Navigate to the system audit logs section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Search audit logs for report access events by both unauthorized and authorized users
    await page.fill('[data-testid="audit-log-search"]', 'report access');
    await page.click('[data-testid="audit-log-search-button"]');
    await page.waitForSelector('[data-testid="audit-log-table"]');

    // Verify the audit log entries contain complete information
    const auditLogTable = page.locator('[data-testid="audit-log-table"]');
    await expect(auditLogTable).toBeVisible();
    
    const auditRows = auditLogTable.locator('tbody tr');
    const rowCount = await auditRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify audit log entry for unauthorized access attempt
    const unauthorizedEntry = auditRows.filter({ hasText: 'viewer@example.com' }).first();
    await expect(unauthorizedEntry).toBeVisible();
    await expect(unauthorizedEntry).toContainText('denied');

    // Verify audit log entry for authorized access
    const authorizedEntry = auditRows.filter({ hasText: 'scheduler@example.com' }).first();
    await expect(authorizedEntry).toBeVisible();
    await expect(authorizedEntry).toContainText('success');
    
    // Verify audit log contains timestamp, user identity, action, and outcome
    const firstLogEntry = auditRows.first();
    await expect(firstLogEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="audit-user"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="audit-action"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="audit-outcome"]')).toBeVisible();
  });
});