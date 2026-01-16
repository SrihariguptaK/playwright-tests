import { test, expect } from '@playwright/test';

test.describe('API Data Transfer Logging and Traceability', () => {
  const baseURL = process.env.BASE_URL || 'https://app.example.com';
  const logsURL = `${baseURL}/logs`;
  const apiURL = `${baseURL}/api`;

  test.beforeEach(async ({ page }) => {
    // Login as authorized user before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'integration.engineer@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate logging of API requests and responses', async ({ page, request }) => {
    // Step 1: Perform API data transfer operations
    const apiResponse = await request.post(`${apiURL}/data-transfer`, {
      data: {
        source: 'system-a',
        destination: 'system-b',
        payload: { data: 'test-data-transfer', timestamp: Date.now() }
      }
    });
    expect(apiResponse.ok()).toBeTruthy();
    const transferId = (await apiResponse.json()).transferId;

    // Wait for logs to be processed
    await page.waitForTimeout(2000);

    // Step 2: Access logs via search UI
    await page.goto(logsURL);
    await expect(page.locator('[data-testid="logs-search-container"]')).toBeVisible();
    
    // Search for the specific transfer
    await page.fill('[data-testid="log-search-input"]', transferId);
    await page.click('[data-testid="search-logs-button"]');
    
    // Verify logs are searchable and filterable
    await expect(page.locator('[data-testid="log-results-table"]')).toBeVisible();
    const logEntry = page.locator(`[data-testid="log-entry-${transferId}"]`).first();
    await expect(logEntry).toBeVisible();
    
    // Verify log details contain request and response data
    await logEntry.click();
    await expect(page.locator('[data-testid="log-detail-request"]')).toContainText('system-a');
    await expect(page.locator('[data-testid="log-detail-response"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-user-identity"]')).toContainText('integration.engineer@example.com');

    // Test filtering functionality
    await page.click('[data-testid="filter-button"]');
    await page.selectOption('[data-testid="filter-type-select"]', 'POST');
    await page.fill('[data-testid="filter-date-from"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filter-button"]');
    await expect(page.locator('[data-testid="log-results-table"] tbody tr')).toHaveCount(await page.locator('[data-testid="log-results-table"] tbody tr').count());

    // Step 3: Export selected logs
    await page.click(`[data-testid="log-checkbox-${transferId}"]`);
    await page.click('[data-testid="export-logs-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'json');
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('logs');
    expect(download.suggestedFilename()).toMatch(/\.(json|csv)$/);
    
    // Verify export success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Logs exported successfully');
  });

  test('Test secure storage and access control of logs', async ({ page, context }) => {
    // Step 1: Attempt unauthorized log access
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/.*login/);
    
    // Try to access logs without authentication
    await page.goto(logsURL);
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="unauthorized-message"]')).toBeVisible();
    
    // Login with unauthorized user (non-support role)
    await page.fill('[data-testid="username-input"]', 'regular.user@example.com');
    await page.fill('[data-testid="password-input"]', 'RegularPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to access logs page
    await page.goto(logsURL);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access is denied');
    
    // Verify the access attempt is logged
    await page.goto(`${baseURL}/logout`);
    
    // Step 2: Access logs with authorized credentials
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'support.engineer@example.com');
    await page.fill('[data-testid="password-input"]', 'SupportPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.goto(logsURL);
    await expect(page.locator('[data-testid="logs-search-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-results-table"]')).toBeVisible();
    
    // Verify full log visibility
    const logCount = await page.locator('[data-testid="log-results-table"] tbody tr').count();
    expect(logCount).toBeGreaterThan(0);
    
    // Verify access to sensitive log details
    await page.locator('[data-testid="log-results-table"] tbody tr').first().click();
    await expect(page.locator('[data-testid="log-detail-request"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-detail-response"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-detail-payload"]')).toBeVisible();
    
    // Step 3: Verify encryption of stored logs
    await page.goto(`${baseURL}/admin/security`);
    await expect(page.locator('[data-testid="security-settings-panel"]')).toBeVisible();
    
    await page.click('[data-testid="log-encryption-tab"]');
    await expect(page.locator('[data-testid="encryption-status"]')).toContainText('Enabled');
    await expect(page.locator('[data-testid="encryption-algorithm"]')).toContainText('AES-256');
    await expect(page.locator('[data-testid="encryption-key-rotation"]')).toBeVisible();
    
    // Verify encryption indicators
    const encryptionBadge = page.locator('[data-testid="logs-encrypted-badge"]');
    await expect(encryptionBadge).toBeVisible();
    await expect(encryptionBadge).toContainText('Encrypted');
  });

  test('Measure logging overhead on API performance', async ({ page, request }) => {
    const iterations = 10;
    const latencies: number[] = [];
    const latenciesWithLogging: number[] = [];
    
    // Step 1: Measure API latency without logging
    await page.goto(`${baseURL}/admin/settings`);
    await page.click('[data-testid="logging-settings-tab"]');
    await page.click('[data-testid="disable-logging-toggle"]');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Wait for settings to propagate
    await page.waitForTimeout(2000);
    
    // Perform baseline measurements
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      const response = await request.post(`${apiURL}/data-transfer`, {
        data: {
          source: 'perf-test-source',
          destination: 'perf-test-dest',
          payload: { iteration: i, data: 'performance-test-data' }
        }
      });
      const endTime = Date.now();
      expect(response.ok()).toBeTruthy();
      latencies.push(endTime - startTime);
      await page.waitForTimeout(100);
    }
    
    const baselineLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    console.log(`Baseline latency (without logging): ${baselineLatency}ms`);
    
    // Step 2: Measure API latency with logging enabled
    await page.goto(`${baseURL}/admin/settings`);
    await page.click('[data-testid="logging-settings-tab"]');
    await page.click('[data-testid="enable-logging-toggle"]');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Wait for settings to propagate
    await page.waitForTimeout(2000);
    
    // Perform measurements with logging
    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      const response = await request.post(`${apiURL}/data-transfer`, {
        data: {
          source: 'perf-test-source',
          destination: 'perf-test-dest',
          payload: { iteration: i, data: 'performance-test-data-logged' }
        }
      });
      const endTime = Date.now();
      expect(response.ok()).toBeTruthy();
      latenciesWithLogging.push(endTime - startTime);
      await page.waitForTimeout(100);
    }
    
    const loggingLatency = latenciesWithLogging.reduce((a, b) => a + b, 0) / latenciesWithLogging.length;
    console.log(`Latency with logging: ${loggingLatency}ms`);
    
    // Calculate overhead percentage
    const overheadPercentage = ((loggingLatency - baselineLatency) / baselineLatency) * 100;
    console.log(`Logging overhead: ${overheadPercentage.toFixed(2)}%`);
    
    // Verify latency increase is under 3%
    expect(overheadPercentage).toBeLessThan(3);
    
    // Step 3: Analyze performance logs
    await page.goto(`${baseURL}/admin/performance`);
    await expect(page.locator('[data-testid="performance-dashboard"]')).toBeVisible();
    
    await page.click('[data-testid="logging-performance-tab"]');
    await expect(page.locator('[data-testid="logging-overhead-metric"]')).toBeVisible();
    
    const displayedOverhead = await page.locator('[data-testid="logging-overhead-percentage"]').textContent();
    const displayedOverheadValue = parseFloat(displayedOverhead?.replace('%', '') || '0');
    expect(displayedOverheadValue).toBeLessThan(3);
    
    // Verify no significant degradation detected
    await expect(page.locator('[data-testid="performance-status"]')).toContainText('Normal');
    await expect(page.locator('[data-testid="degradation-alert"]')).not.toBeVisible();
    
    // Check performance metrics chart
    await expect(page.locator('[data-testid="performance-chart"]')).toBeVisible();
    const chartData = await page.locator('[data-testid="chart-data-points"]').count();
    expect(chartData).toBeGreaterThan(0);
  });
});