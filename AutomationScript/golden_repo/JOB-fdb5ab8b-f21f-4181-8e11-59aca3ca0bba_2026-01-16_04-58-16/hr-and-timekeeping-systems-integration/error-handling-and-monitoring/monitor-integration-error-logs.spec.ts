import { test, expect } from '@playwright/test';

test.describe('Monitor Integration Error Logs', () => {
  const DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://app.example.com/monitoring';
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AdminPass123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to monitoring dashboard and login
    await page.goto(DASHBOARD_URL);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Verify centralized aggregation of integration error logs', async ({ page }) => {
    // Generate integration errors in test environment by simulating various failure scenarios
    const testErrors = [
      { type: 'API_TIMEOUT', severity: 'HIGH', message: 'API request timeout after 30s' },
      { type: 'DATABASE_CONNECTION', severity: 'CRITICAL', message: 'Database connection failure' },
      { type: 'AUTHENTICATION_ERROR', severity: 'MEDIUM', message: 'Authentication token expired' }
    ];

    // Simulate error generation via API or test trigger endpoint
    for (const error of testErrors) {
      await page.request.post(`${DASHBOARD_URL}/api/test/generate-error`, {
        data: error
      });
    }

    // Access the error logs section of the monitoring dashboard
    await page.click('[data-testid="error-logs-menu"]');
    await expect(page.locator('[data-testid="error-logs-section"]')).toBeVisible();

    // Verify that error count matches the number of errors generated
    const errorCount = await page.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBeGreaterThanOrEqual(testErrors.length);

    // Verify all generated errors displayed with correct details
    for (const error of testErrors) {
      const errorRow = page.locator(`[data-testid="error-row"]`, { hasText: error.message });
      await expect(errorRow).toBeVisible();
    }

    // Apply filter by selecting specific error type from the filter dropdown
    await page.click('[data-testid="error-type-filter"]');
    await page.click('[data-testid="filter-option-API_TIMEOUT"]');
    await page.waitForTimeout(1000); // Wait for filter to apply

    // Verify filtered results match criteria accurately
    const filteredRows = page.locator('[data-testid="error-row"]');
    const filteredCount = await filteredRows.count();
    expect(filteredCount).toBeGreaterThan(0);
    
    for (let i = 0; i < filteredCount; i++) {
      const errorType = await filteredRows.nth(i).locator('[data-testid="error-type"]').textContent();
      expect(errorType).toContain('API_TIMEOUT');
    }

    // Clear the error type filter and apply date range filter for today's date
    await page.click('[data-testid="clear-filters-button"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-filter-today"]');
    await page.waitForTimeout(1000);

    // Verify date filtered results
    const dateFilteredRows = page.locator('[data-testid="error-row"]');
    expect(await dateFilteredRows.count()).toBeGreaterThan(0);

    // Apply combined filters for error type and date range simultaneously
    await page.click('[data-testid="error-type-filter"]');
    await page.click('[data-testid="filter-option-DATABASE_CONNECTION"]');
    await page.waitForTimeout(1000);

    // Verify combined filter results
    const combinedFilteredRows = page.locator('[data-testid="error-row"]');
    const combinedCount = await combinedFilteredRows.count();
    
    if (combinedCount > 0) {
      const errorType = await combinedFilteredRows.first().locator('[data-testid="error-type"]').textContent();
      expect(errorType).toContain('DATABASE_CONNECTION');
    }
  });

  test('Test real-time alerting on critical errors', async ({ page }) => {
    // Note the current system time before triggering the error
    const errorTriggerTime = new Date();

    // Trigger a critical integration error in the test environment
    await page.request.post(`${DASHBOARD_URL}/api/test/generate-error`, {
      data: {
        type: 'DATABASE_CONNECTION',
        severity: 'CRITICAL',
        message: 'Complete database connection failure - all nodes unreachable'
      }
    });

    // Navigate to the alerts section in the dashboard
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();

    // Wait for alert to appear (should be within 1 minute)
    await page.waitForSelector('[data-testid="alert-item"]', { timeout: 65000 });

    // Verify the alert delivery timestamp against the error occurrence time
    const alertTimestamp = await page.locator('[data-testid="alert-timestamp"]').first().textContent();
    expect(alertTimestamp).toBeTruthy();

    // Verify alert contains correct error details
    const alertMessage = page.locator('[data-testid="alert-item"]').first();
    await expect(alertMessage).toContainText('Complete database connection failure');
    await expect(alertMessage).toContainText('CRITICAL');

    // Click on the alert and select 'Acknowledge' button
    await alertMessage.click();
    await page.click('[data-testid="acknowledge-alert-button"]');

    // Verify alert status updated and logged
    await expect(page.locator('[data-testid="alert-status"]').first()).toContainText('Acknowledged');

    // Navigate to the alert history section in the dashboard
    await page.click('[data-testid="alert-history-tab"]');
    await expect(page.locator('[data-testid="alert-history-section"]')).toBeVisible();

    // Verify alert history accurately reflects actions taken
    const historyEntry = page.locator('[data-testid="history-entry"]').first();
    await expect(historyEntry).toContainText('Acknowledged');
    await expect(historyEntry).toBeVisible();

    // Verify alert resolution tracking by updating the alert status to 'Resolved' with resolution notes
    await page.click('[data-testid="alerts-menu"]');
    await alertMessage.click();
    await page.click('[data-testid="resolve-alert-button"]');
    await page.fill('[data-testid="resolution-notes-input"]', 'Database connection restored after server restart');
    await page.click('[data-testid="submit-resolution-button"]');

    // Verify resolution status updated
    await expect(page.locator('[data-testid="alert-status"]').first()).toContainText('Resolved');
  });

  test('Validate export functionality of error logs', async ({ page }) => {
    // Navigate to the error logs section
    await page.click('[data-testid="error-logs-menu"]');
    await expect(page.locator('[data-testid="error-logs-section"]')).toBeVisible();

    // Apply filters to select specific error logs (e.g., errors from the last 24 hours)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-filter-last-24-hours"]');
    await page.waitForTimeout(1000);

    // Select multiple error log entries using checkboxes or select all option
    await page.click('[data-testid="select-all-errors-checkbox"]');
    
    // Verify selection
    const selectedCount = await page.locator('[data-testid="selected-count"]').textContent();
    expect(parseInt(selectedCount || '0')).toBeGreaterThan(0);

    // Click on the 'Export' button in the dashboard toolbar
    await page.click('[data-testid="export-button"]');

    // Verify export options for CSV and JSON displayed
    await expect(page.locator('[data-testid="export-csv-option"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-json-option"]')).toBeVisible();

    // Select 'CSV' format from the export options and click 'Download' button
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-option"]')
    ]);

    // Verify CSV file downloaded with correct data
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Read and verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('id');
    expect(csvContent).toContain('timestamp');
    expect(csvContent).toContain('errorType');
    expect(csvContent).toContain('severity');

    // Return to the dashboard and click 'Export' button again, this time selecting 'JSON' format
    await page.click('[data-testid="export-button"]');

    // Click 'Download' button to export in JSON format
    const [jsonDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-json-option"]')
    ]);

    // Verify JSON file downloaded with correct data structure
    expect(jsonDownload.suggestedFilename()).toContain('.json');
    const jsonPath = await jsonDownload.path();
    expect(jsonPath).toBeTruthy();

    // Open and validate JSON structure
    const jsonContent = fs.readFileSync(jsonPath, 'utf-8');
    const jsonData = JSON.parse(jsonContent);

    // Validate JSON structure and verify it contains all required fields
    expect(Array.isArray(jsonData)).toBeTruthy();
    expect(jsonData.length).toBeGreaterThan(0);

    const firstEntry = jsonData[0];
    expect(firstEntry).toHaveProperty('id');
    expect(firstEntry).toHaveProperty('timestamp');
    expect(firstEntry).toHaveProperty('errorType');
    expect(firstEntry).toHaveProperty('severity');
    expect(firstEntry).toHaveProperty('sourceComponent');
    expect(firstEntry).toHaveProperty('errorMessage');
    expect(firstEntry).toHaveProperty('status');

    // Verify data integrity by comparing sample entries with dashboard display
    const firstErrorInDashboard = await page.locator('[data-testid="error-row"]').first();
    const dashboardErrorType = await firstErrorInDashboard.locator('[data-testid="error-type"]').textContent();
    const dashboardErrorMessage = await firstErrorInDashboard.locator('[data-testid="error-message"]').textContent();

    expect(jsonData.some((entry: any) => 
      entry.errorType === dashboardErrorType?.trim() || 
      entry.errorMessage.includes(dashboardErrorMessage?.trim() || '')
    )).toBeTruthy();
  });
});