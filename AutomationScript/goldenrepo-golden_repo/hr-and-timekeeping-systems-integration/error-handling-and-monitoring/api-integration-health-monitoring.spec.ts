import { test, expect } from '@playwright/test';

test.describe('API Integration Health Monitoring - Story 17', () => {
  const baseURL = process.env.BASE_URL || 'https://app.example.com';
  const monitoringDashboardURL = `${baseURL}/monitoring/dashboard`;
  const supportEngineerEmail = 'support.engineer@example.com';
  const supportEngineerPassword = 'SecurePass123!';

  test.beforeEach(async ({ page }) => {
    // Login as Support Engineer before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', supportEngineerEmail);
    await page.fill('[data-testid="password-input"]', supportEngineerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate real-time API health metrics display', async ({ page }) => {
    // Step 1: Access monitoring dashboard
    await page.goto(monitoringDashboardURL);
    await page.waitForSelector('[data-testid="monitoring-dashboard"]');
    
    // Expected Result: Dashboard displays current API health metrics
    await expect(page.locator('[data-testid="api-health-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-rate-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-time-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="api-status-indicator"]')).toBeVisible();
    
    // Capture initial error count
    const initialErrorCount = await page.locator('[data-testid="error-count"]').textContent();
    
    // Step 2: Simulate API errors
    await page.click('[data-testid="simulate-errors-button"]');
    await page.fill('[data-testid="error-count-input"]', '5');
    await page.click('[data-testid="trigger-errors-button"]');
    
    // Expected Result: Error metrics update in real-time on dashboard
    await page.waitForTimeout(2000); // Wait for metrics to update
    const updatedErrorCount = await page.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(updatedErrorCount || '0')).toBeGreaterThan(parseInt(initialErrorCount || '0'));
    await expect(page.locator('[data-testid="error-rate-metric"]')).toContainText(/[0-9]+/);
    
    // Step 3: Verify dashboard refresh interval
    const firstTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    
    // Expected Result: Metrics refresh at least once per minute
    await page.waitForTimeout(61000); // Wait for 61 seconds
    const secondTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(firstTimestamp).not.toBe(secondTimestamp);
  });

  test('Test alert configuration and notification', async ({ page }) => {
    // Step 1: Set alert threshold for error rate
    await page.goto(monitoringDashboardURL);
    await page.click('[data-testid="configure-alerts-button"]');
    await page.waitForSelector('[data-testid="alert-configuration-modal"]');
    
    await page.selectOption('[data-testid="metric-selector"]', 'error-rate');
    await page.fill('[data-testid="threshold-value-input"]', '10');
    await page.selectOption('[data-testid="threshold-operator"]', 'greater-than');
    await page.fill('[data-testid="notification-email"]', 'support-team@example.com');
    await page.click('[data-testid="save-alert-button"]');
    
    // Expected Result: Threshold is saved and active
    await expect(page.locator('[data-testid="alert-success-message"]')).toContainText('Alert threshold saved successfully');
    await page.click('[data-testid="close-modal-button"]');
    await expect(page.locator('[data-testid="active-alerts-list"]')).toContainText('error-rate');
    await expect(page.locator('[data-testid="alert-status"]')).toContainText('Active');
    
    // Step 2: Simulate error rate exceeding threshold
    await page.click('[data-testid="simulate-errors-button"]');
    await page.fill('[data-testid="error-rate-input"]', '15');
    await page.click('[data-testid="trigger-high-error-rate-button"]');
    
    // Expected Result: Alert notification is sent to support team
    await page.waitForTimeout(3000); // Wait for alert processing
    await expect(page.locator('[data-testid="alert-notification-banner"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-notification-banner"]')).toContainText('Error rate threshold exceeded');
    
    // Verify notification in alerts panel
    await page.click('[data-testid="alerts-panel-button"]');
    await expect(page.locator('[data-testid="recent-alerts-list"]')).toContainText('error-rate');
    await expect(page.locator('[data-testid="alert-severity"]').first()).toContainText('Critical');
    
    // Step 3: Acknowledge alert in dashboard
    await page.click('[data-testid="acknowledge-alert-button"]');
    await page.fill('[data-testid="acknowledgment-note"]', 'Investigating high error rate');
    await page.click('[data-testid="confirm-acknowledgment-button"]');
    
    // Expected Result: Alert status updates accordingly
    await expect(page.locator('[data-testid="alert-status"]').first()).toContainText('Acknowledged');
    await expect(page.locator('[data-testid="acknowledged-by"]')).toContainText(supportEngineerEmail);
  });

  test('Verify historical trend data availability', async ({ page }) => {
    // Step 1: Access historical performance section
    await page.goto(monitoringDashboardURL);
    await page.click('[data-testid="historical-trends-tab"]');
    await page.waitForSelector('[data-testid="trend-charts-container"]');
    
    // Expected Result: Trend charts display API metrics over selected periods
    await expect(page.locator('[data-testid="error-rate-trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="response-time-trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="throughput-trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-data-points"]')).toHaveCount({ timeout: 5000 });
    
    // Step 2: Select different time ranges
    const timeRanges = ['last-hour', 'last-24-hours', 'last-7-days', 'last-30-days'];
    
    for (const timeRange of timeRanges) {
      await page.selectOption('[data-testid="time-range-selector"]', timeRange);
      await page.waitForTimeout(1000); // Wait for chart to update
      
      // Expected Result: Charts update to reflect selected time frames
      await expect(page.locator('[data-testid="selected-time-range"]')).toContainText(timeRange.replace('-', ' '));
      await expect(page.locator('[data-testid="chart-loading-indicator"]')).not.toBeVisible();
      const chartTitle = await page.locator('[data-testid="chart-title"]').first().textContent();
      expect(chartTitle).toBeTruthy();
    }
    
    // Step 3: Export trend data
    await page.selectOption('[data-testid="time-range-selector"]', 'last-7-days');
    await page.click('[data-testid="export-data-button"]');
    await page.waitForSelector('[data-testid="export-options-modal"]');
    
    await page.selectOption('[data-testid="export-format-selector"]', 'csv');
    await page.check('[data-testid="include-error-rate-checkbox"]');
    await page.check('[data-testid="include-response-time-checkbox"]');
    await page.check('[data-testid="include-throughput-checkbox"]');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Expected Result: Data is exported in CSV format successfully
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Data exported successfully');
  });

  test('Validate logging of API requests and responses (happy-path)', async ({ page }) => {
    // Authenticate to the API system with valid credentials (already done in beforeEach)
    await page.goto(`${baseURL}/api-management`);
    
    // Perform multiple API data transfer operations including GET, POST, PUT, and DELETE requests
    await page.click('[data-testid="api-testing-console"]');
    await page.waitForSelector('[data-testid="api-console-panel"]');
    
    // Execute GET request
    await page.selectOption('[data-testid="http-method-selector"]', 'GET');
    await page.fill('[data-testid="endpoint-input"]', '/api/v1/users');
    await page.click('[data-testid="send-request-button"]');
    await expect(page.locator('[data-testid="response-status"]')).toContainText('200');
    
    // Execute POST request
    await page.selectOption('[data-testid="http-method-selector"]', 'POST');
    await page.fill('[data-testid="endpoint-input"]', '/api/v1/users');
    await page.fill('[data-testid="request-body-input"]', '{"name":"Test User","email":"test@example.com"}');
    await page.click('[data-testid="send-request-button"]');
    await expect(page.locator('[data-testid="response-status"]')).toContainText('201');
    
    // Execute PUT request
    await page.selectOption('[data-testid="http-method-selector"]', 'PUT');
    await page.fill('[data-testid="endpoint-input"]', '/api/v1/users/123');
    await page.fill('[data-testid="request-body-input"]', '{"name":"Updated User"}');
    await page.click('[data-testid="send-request-button"]');
    await expect(page.locator('[data-testid="response-status"]')).toContainText('200');
    
    // Execute DELETE request
    await page.selectOption('[data-testid="http-method-selector"]', 'DELETE');
    await page.fill('[data-testid="endpoint-input"]', '/api/v1/users/123');
    await page.click('[data-testid="send-request-button"]');
    await expect(page.locator('[data-testid="response-status"]')).toContainText('204');
    
    // Verify that all requests and responses are logged with complete details
    await page.goto(`${baseURL}/logs`);
    await page.waitForSelector('[data-testid="log-search-ui"]');
    
    // Navigate to the log search UI interface
    await expect(page.locator('[data-testid="log-search-interface"]')).toBeVisible();
    
    // Search for logs using various criteria
    await page.fill('[data-testid="search-endpoint-input"]', '/api/v1/users');
    await page.click('[data-testid="search-logs-button"]');
    await page.waitForSelector('[data-testid="log-results-table"]');
    
    // Verify log entries contain required details
    const logEntries = page.locator('[data-testid="log-entry-row"]');
    await expect(logEntries).toHaveCount(4); // GET, POST, PUT, DELETE
    
    const firstLogEntry = logEntries.first();
    await expect(firstLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-user-identity"]')).toContainText(supportEngineerEmail);
    await expect(firstLogEntry.locator('[data-testid="log-endpoint"]')).toContainText('/api/v1/users');
    await expect(firstLogEntry.locator('[data-testid="log-http-method"]')).toBeVisible();
    await expect(firstLogEntry.locator('[data-testid="log-status-code"]')).toBeVisible();
    
    // Search using timestamp range
    const currentDate = new Date();
    const startDate = new Date(currentDate.getTime() - 3600000); // 1 hour ago
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', currentDate.toISOString().split('T')[0]);
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="log-entry-row"]')).toHaveCount(4);
    
    // Search by HTTP method
    await page.selectOption('[data-testid="method-filter"]', 'POST');
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="log-entry-row"]')).toHaveCount(1);
    await expect(page.locator('[data-testid="log-http-method"]').first()).toContainText('POST');
    
    // Select specific logs and export
    await page.click('[data-testid="clear-filters-button"]');
    await page.click('[data-testid="search-logs-button"]');
    await page.check('[data-testid="select-log-checkbox"]');
    await page.click('[data-testid="export-logs-button"]');
    
    // Select desired export format and confirm export action
    await page.waitForSelector('[data-testid="export-format-modal"]');
    await page.selectOption('[data-testid="export-format-select"]', 'csv');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-logs-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/logs.*\.csv/);
  });

  test('Test secure storage and access control of logs (error-case)', async ({ page }) => {
    // Logout first to test unauthorized access
    await page.goto(`${baseURL}/logout`);
    
    // Step 1: Attempt to access log storage or log search UI using unauthorized credentials
    await page.goto(`${baseURL}/logs`);
    
    // Expected Result: Redirected to login or access denied
    await expect(page).toHaveURL(/.*login/);
    
    // Attempt direct access to log search UI
    await page.goto(`${baseURL}/logs/search`);
    await expect(page).toHaveURL(/.*login/);
    
    // Try with invalid credentials
    await page.fill('[data-testid="email-input"]', 'unauthorized@example.com');
    await page.fill('[data-testid="password-input"]', 'WrongPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials');
    
    // Step 2: Verify that the unauthorized access attempt is logged in the audit trail
    // Login with authorized credentials to check audit trail
    await page.fill('[data-testid="email-input"]', supportEngineerEmail);
    await page.fill('[data-testid="password-input"]', supportEngineerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.goto(`${baseURL}/audit-trail`);
    await page.waitForSelector('[data-testid="audit-log-table"]');
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized access');
    await page.click('[data-testid="audit-search-button"]');
    
    // Expected Result: Unauthorized access attempt is logged
    await expect(page.locator('[data-testid="audit-entry"]').first()).toContainText('Unauthorized access attempt');
    await expect(page.locator('[data-testid="audit-entry"]').first()).toContainText('unauthorized@example.com');
    
    // Step 3: Authenticate with authorized Support Engineer credentials
    await page.goto(`${baseURL}/logs`);
    await page.waitForSelector('[data-testid="log-search-ui"]');
    
    // Expected Result: Access logs via the search UI and verify full visibility
    await expect(page.locator('[data-testid="log-search-interface"]')).toBeVisible();
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="log-entry-row"]')).toHaveCount({ timeout: 5000 });
    
    // Step 4: Navigate to log storage location and inspect stored log files
    await page.goto(`${baseURL}/system/log-storage`);
    await page.waitForSelector('[data-testid="log-storage-panel"]');
    
    // Expected Result: Verify encryption of stored logs
    await expect(page.locator('[data-testid="encryption-status"]')).toContainText('Encrypted');
    await expect(page.locator('[data-testid="encryption-algorithm"]')).toContainText('AES-256');
    
    // Check file properties
    await page.click('[data-testid="log-file-row"]');
    await page.click('[data-testid="view-properties-button"]');
    await expect(page.locator('[data-testid="file-encryption-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="encryption-key-location"]')).toContainText('Secure Key Vault');
    
    // Step 5: Verify that encryption keys are stored securely and separately
    await page.goto(`${baseURL}/system/security-settings`);
    await page.click('[data-testid="encryption-keys-tab"]');
    await expect(page.locator('[data-testid="key-storage-location"]')).toContainText('Separate Key Management Service');
    await expect(page.locator('[data-testid="key-separation-status"]')).toContainText('Keys stored separately from data');
  });

  test('Measure logging overhead on API performance (boundary)', async ({ page }) => {
    await page.goto(`${baseURL}/system/performance-testing`);
    await page.waitForSelector('[data-testid="performance-test-panel"]');
    
    // Step 1: Disable logging functionality in the API system
    await page.click('[data-testid="logging-settings-button"]');
    await page.waitForSelector('[data-testid="logging-config-modal"]');
    await page.uncheck('[data-testid="enable-logging-checkbox"]');
    await page.click('[data-testid="save-logging-config-button"]');
    await expect(page.locator('[data-testid="logging-status"]')).toContainText('Disabled');
    
    // Step 2: Execute a series of API requests (minimum 1000 requests)
    await page.click('[data-testid="performance-test-tab"]');
    await page.fill('[data-testid="request-count-input"]', '1000');
    await page.selectOption('[data-testid="endpoint-selector"]', 'mixed-endpoints');
    await page.click('[data-testid="run-baseline-test-button"]');
    
    // Wait for test completion
    await page.waitForSelector('[data-testid="test-complete-indicator"]', { timeout: 120000 });
    
    // Step 3: Document baseline performance metrics
    const baselineLatency = await page.locator('[data-testid="average-latency"]').textContent();
    const baselineThroughput = await page.locator('[data-testid="throughput"]').textContent();
    const baselineResponseTime = await page.locator('[data-testid="average-response-time"]').textContent();
    
    await expect(page.locator('[data-testid="baseline-metrics-saved"]')).toBeVisible();
    
    // Step 4: Enable comprehensive logging functionality
    await page.click('[data-testid="logging-settings-button"]');
    await page.waitForSelector('[data-testid="logging-config-modal"]');
    await page.check('[data-testid="enable-logging-checkbox"]');
    await page.check('[data-testid="log-requests-checkbox"]');
    await page.check('[data-testid="log-responses-checkbox"]');
    await page.check('[data-testid="log-headers-checkbox"]');
    await page.check('[data-testid="log-payloads-checkbox"]');
    await page.click('[data-testid="save-logging-config-button"]');
    await expect(page.locator('[data-testid="logging-status"]')).toContainText('Enabled');
    
    // Step 5: Execute the same series of API requests with logging enabled
    await page.click('[data-testid="performance-test-tab"]');
    await page.fill('[data-testid="request-count-input"]', '1000');
    await page.selectOption('[data-testid="endpoint-selector"]', 'mixed-endpoints');
    await page.click('[data-testid="run-logging-test-button"]');
    
    await page.waitForSelector('[data-testid="test-complete-indicator"]', { timeout: 120000 });
    
    // Step 6: Calculate the percentage increase in latency
    const loggingLatency = await page.locator('[data-testid="average-latency"]').textContent();
    const loggingThroughput = await page.locator('[data-testid="throughput"]').textContent();
    const loggingResponseTime = await page.locator('[data-testid="average-response-time"]').textContent();
    
    await page.click('[data-testid="compare-results-button"]');
    await page.waitForSelector('[data-testid="comparison-results"]');
    
    // Expected Result: Verify performance impact is within acceptable range
    const latencyIncrease = await page.locator('[data-testid="latency-increase-percentage"]').textContent();
    const latencyIncreaseValue = parseFloat(latencyIncrease?.replace('%', '') || '0');
    
    // Verify latency increase is documented
    expect(latencyIncreaseValue).toBeGreaterThanOrEqual(0);
    expect(latencyIncreaseValue).toBeLessThan(20); // Assuming 20% is acceptable threshold
    
    // Step 7: Analyze performance logs and system resource utilization
    await page.click('[data-testid="resource-utilization-tab"]');
    await expect(page.locator('[data-testid="cpu-usage-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="memory-usage-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="io-usage-chart"]')).toBeVisible();
    
    // Verify comparison data is available
    await expect(page.locator('[data-testid="baseline-cpu-usage"]')).toBeVisible();
    await expect(page.locator('[data-testid="logging-cpu-usage"]')).toBeVisible();
    
    // Step 8: Review logging throughput and verify no log entries are dropped
    await page.click('[data-testid="logging-throughput-tab"]');
    await expect(page.locator('[data-testid="total-requests-processed"]')).toContainText('1000');
    await expect(page.locator('[data-testid="total-logs-written"]')).toContainText('1000');
    
    const droppedLogs = await page.locator('[data-testid="dropped-logs-count"]').textContent();
    expect(parseInt(droppedLogs || '0')).toBe(0);
    
    const delayedLogs = await page.locator('[data-testid="delayed-logs-count"]').textContent();
    expect(parseInt(delayedLogs || '0')).toBe(0);
  });
});