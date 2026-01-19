import { test, expect } from '@playwright/test';

test.describe('Timekeeping Data Import Error Handling and Retries', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Navigate to payroll specialist dashboard
    await page.goto(`${BASE_URL}/payroll/dashboard`);
    await expect(page).toHaveTitle(/Payroll Dashboard/);
  });

  test('Verify error detection and logging during import', async ({ page, request }) => {
    // Configure test scenario to simulate an import error
    await page.goto(`${BASE_URL}/payroll/timekeeping/import`);
    await page.waitForSelector('[data-testid="import-config-panel"]');
    
    // Set up error simulation for API timeout
    await page.click('[data-testid="test-settings-toggle"]');
    await page.selectOption('[data-testid="error-simulation-type"]', 'api_timeout');
    await page.click('[data-testid="enable-error-simulation"]');
    
    // Initiate timekeeping data import job that will encounter the simulated error
    await page.click('[data-testid="start-import-button"]');
    
    // Monitor import process as it encounters the simulated error condition
    await page.waitForSelector('[data-testid="import-status"]');
    const importStatus = await page.locator('[data-testid="import-status"]').textContent();
    expect(importStatus).toContain('Error');
    
    // Access error logs and locate the entry for the detected import error
    await page.click('[data-testid="view-error-logs"]');
    await page.waitForSelector('[data-testid="error-log-entries"]');
    
    const errorLogEntry = page.locator('[data-testid="error-log-entry"]').first();
    await expect(errorLogEntry).toBeVisible();
    
    // Verify error log contains sufficient information for troubleshooting
    const errorDetails = await errorLogEntry.locator('[data-testid="error-details"]').textContent();
    expect(errorDetails).toContain('api_timeout');
    expect(errorDetails).toMatch(/timestamp/i);
    
    const stackTrace = await errorLogEntry.locator('[data-testid="error-stacktrace"]').textContent();
    expect(stackTrace).toBeTruthy();
    expect(stackTrace.length).toBeGreaterThan(0);
    
    // Check that error logging is secure and does not expose sensitive data
    const logContent = await errorLogEntry.textContent();
    expect(logContent).not.toMatch(/password|secret|token|api[_-]?key/i);
    
    // Verify error detection does not cause system crash or data corruption
    await page.goto(`${BASE_URL}/payroll/dashboard`);
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    
    // Verify system is still responsive
    const response = await request.get(`${API_URL}/health`);
    expect(response.ok()).toBeTruthy();
  });

  test('Verify automatic retry of failed imports', async ({ page }) => {
    // Configure test scenario to cause a transient import failure
    await page.goto(`${BASE_URL}/payroll/timekeeping/import`);
    await page.waitForSelector('[data-testid="import-config-panel"]');
    
    // Set up transient failure simulation (temporary network issue)
    await page.click('[data-testid="test-settings-toggle"]');
    await page.selectOption('[data-testid="error-simulation-type"]', 'transient_network_error');
    await page.fill('[data-testid="error-duration"]', '5000'); // 5 seconds
    await page.click('[data-testid="enable-error-simulation"]');
    
    // Configure retry settings
    await page.click('[data-testid="retry-settings"]');
    await page.fill('[data-testid="max-retry-attempts"]', '3');
    await page.fill('[data-testid="retry-interval"]', '2000'); // 2 seconds
    await page.click('[data-testid="save-retry-settings"]');
    
    // Initiate timekeeping data import job that will encounter the transient failure
    await page.click('[data-testid="start-import-button"]');
    
    // Monitor system response to the initial failure
    await page.waitForSelector('[data-testid="import-status"]');
    const initialStatus = await page.locator('[data-testid="import-status"]').textContent();
    expect(initialStatus).toMatch(/Failed|Error/);
    
    // Observe that system automatically initiates retry attempt
    await page.waitForSelector('[data-testid="retry-indicator"]', { timeout: 10000 });
    const retryIndicator = await page.locator('[data-testid="retry-indicator"]').textContent();
    expect(retryIndicator).toMatch(/Retrying|Retry attempt/i);
    
    // Allow the transient issue to resolve and monitor the retry attempt
    await page.waitForSelector('[data-testid="import-status"]:has-text("Success")', { timeout: 15000 });
    const finalStatus = await page.locator('[data-testid="import-status"]').textContent();
    expect(finalStatus).toContain('Success');
    
    // Access import logs and verify retry attempts are documented
    await page.click('[data-testid="view-import-logs"]');
    await page.waitForSelector('[data-testid="import-log-entries"]');
    
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(1); // Initial attempt + retry
    
    const retryLog = logEntries.filter({ hasText: /retry/i }).first();
    await expect(retryLog).toBeVisible();
    
    // Verify imported data in payroll system matches source timekeeping data
    await page.goto(`${BASE_URL}/payroll/timekeeping/data`);
    await page.waitForSelector('[data-testid="imported-data-table"]');
    
    const dataRows = page.locator('[data-testid="data-row"]');
    const rowCount = await dataRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Check that success metrics show 95% or higher resolution rate
    await page.goto(`${BASE_URL}/payroll/timekeeping/metrics`);
    await page.waitForSelector('[data-testid="success-rate-metric"]');
    
    const successRateText = await page.locator('[data-testid="success-rate-metric"]').textContent();
    const successRate = parseFloat(successRateText.replace(/[^0-9.]/g, ''));
    expect(successRate).toBeGreaterThanOrEqual(95);
  });

  test('Verify notification on persistent import failure', async ({ page }) => {
    // Configure test scenario to cause a persistent import failure
    await page.goto(`${BASE_URL}/payroll/timekeeping/import`);
    await page.waitForSelector('[data-testid="import-config-panel"]');
    
    // Set up persistent failure simulation (invalid API credentials)
    await page.click('[data-testid="test-settings-toggle"]');
    await page.selectOption('[data-testid="error-simulation-type"]', 'invalid_credentials');
    await page.click('[data-testid="enable-error-simulation"]');
    
    // Configure retry settings with lower max attempts for faster test
    await page.click('[data-testid="retry-settings"]');
    await page.fill('[data-testid="max-retry-attempts"]', '3');
    await page.fill('[data-testid="retry-interval"]', '1000'); // 1 second
    await page.click('[data-testid="save-retry-settings"]');
    
    // Initiate timekeeping data import job that will encounter the persistent failure
    await page.click('[data-testid="start-import-button"]');
    
    // Monitor system as it detects the failure and logs the error
    await page.waitForSelector('[data-testid="import-status"]');
    const initialStatus = await page.locator('[data-testid="import-status"]').textContent();
    expect(initialStatus).toMatch(/Failed|Error/);
    
    // Observe first automatic retry attempt
    await page.waitForSelector('[data-testid="retry-counter"]', { timeout: 5000 });
    let retryCount = await page.locator('[data-testid="retry-counter"]').textContent();
    expect(retryCount).toContain('1');
    
    // Monitor subsequent retry attempts until maximum retry limit is reached
    await page.waitForSelector('[data-testid="retry-counter"]:has-text("3")', { timeout: 10000 });
    retryCount = await page.locator('[data-testid="retry-counter"]').textContent();
    expect(retryCount).toContain('3');
    
    // Verify that after maximum retry attempts are exhausted, system triggers notification
    await page.waitForSelector('[data-testid="max-retries-exceeded"]', { timeout: 5000 });
    const maxRetriesMessage = await page.locator('[data-testid="max-retries-exceeded"]').textContent();
    expect(maxRetriesMessage).toMatch(/maximum retry attempts|retries exhausted/i);
    
    // Check payroll team notification inbox for alert
    await page.goto(`${BASE_URL}/notifications`);
    await page.waitForSelector('[data-testid="notification-list"]');
    
    const notifications = page.locator('[data-testid="notification-item"]');
    const importFailureNotification = notifications.filter({ hasText: /import failure|timekeeping import failed/i }).first();
    await expect(importFailureNotification).toBeVisible();
    
    // Verify notification contains actionable information
    await importFailureNotification.click();
    await page.waitForSelector('[data-testid="notification-details"]');
    
    const notificationDetails = await page.locator('[data-testid="notification-details"]').textContent();
    expect(notificationDetails).toMatch(/invalid_credentials|authentication/i);
    expect(notificationDetails).toContain('3'); // Max retry attempts
    
    const notificationTimestamp = await page.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();
    
    // Access import logs and verify all retry attempts and outcomes are documented
    await page.goto(`${BASE_URL}/payroll/timekeeping/import/logs`);
    await page.waitForSelector('[data-testid="import-log-entries"]');
    
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThanOrEqual(4); // Initial attempt + 3 retries
    
    // Verify each retry attempt is logged
    for (let i = 1; i <= 3; i++) {
      const retryLog = logEntries.filter({ hasText: new RegExp(`retry.*${i}`, 'i') });
      await expect(retryLog.first()).toBeVisible();
    }
    
    // Confirm no data loss occurred despite import failure
    await page.goto(`${BASE_URL}/payroll/timekeeping/data`);
    await page.waitForSelector('[data-testid="data-integrity-status"]');
    
    const dataIntegrityStatus = await page.locator('[data-testid="data-integrity-status"]').textContent();
    expect(dataIntegrityStatus).toMatch(/intact|no data loss|consistent/i);
    
    // Verify existing data was not corrupted
    const existingDataCount = await page.locator('[data-testid="data-row"]').count();
    await page.reload();
    await page.waitForSelector('[data-testid="data-row"]');
    const reloadedDataCount = await page.locator('[data-testid="data-row"]').count();
    expect(reloadedDataCount).toBe(existingDataCount);
  });
});