import { test, expect } from '@playwright/test';

test.describe('Data Ingestion Health Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to admin login
    await page.goto('/admin/login');
    
    // Login as admin
    await page.fill('[data-testid="username-input"]', 'admin@attendance.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await page.waitForURL('**/admin/dashboard');
  });

  test('Validate ingestion health dashboard displays accurate status - happy path', async ({ page }) => {
    // Navigate to the ingestion health monitoring dashboard
    await page.click('[data-testid="monitoring-menu"]');
    await page.click('[data-testid="ingestion-health-link"]');
    await page.waitForURL('**/admin/monitoring/ingestion-health');
    
    // Verify dashboard is loaded
    await expect(page.locator('[data-testid="ingestion-dashboard"]')).toBeVisible();
    
    // Simulate normal data ingestion by triggering a standard data feed from attendance sources
    await page.click('[data-testid="simulate-ingestion-button"]');
    await page.selectOption('[data-testid="simulation-type-select"]', 'normal');
    await page.click('[data-testid="start-simulation-button"]');
    
    // Wait for simulation to start
    await page.waitForTimeout(2000);
    
    // Verify all metrics on the dashboard are updating in real-time
    await expect(page.locator('[data-testid="ingestion-status"]')).toHaveText('Healthy', { timeout: 10000 });
    await expect(page.locator('[data-testid="ingestion-rate-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="records-processed-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-update-timestamp"]')).toBeVisible();
    
    // Verify metrics are showing positive values
    const recordsProcessed = await page.locator('[data-testid="records-processed-metric"]').textContent();
    expect(parseInt(recordsProcessed || '0')).toBeGreaterThan(0);
    
    // Verify status indicator is green/healthy
    await expect(page.locator('[data-testid="status-indicator"]')).toHaveClass(/healthy|success|green/);
    
    // Simulate ingestion failure by stopping the data source or introducing a connection error
    await page.click('[data-testid="simulate-ingestion-button"]');
    await page.selectOption('[data-testid="simulation-type-select"]', 'failure');
    await page.selectOption('[data-testid="failure-type-select"]', 'connection-error');
    await page.click('[data-testid="start-simulation-button"]');
    
    // Wait for failure to be detected
    await page.waitForTimeout(3000);
    
    // Verify dashboard shows failure status
    await expect(page.locator('[data-testid="ingestion-status"]')).toHaveText(/Failed|Error|Unhealthy/, { timeout: 10000 });
    await expect(page.locator('[data-testid="status-indicator"]')).toHaveClass(/failed|error|red/);
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('connection error');
    
    // Check for alert notification sent to administrators
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const alertNotification = page.locator('[data-testid="alert-notification"]').first();
    await expect(alertNotification).toBeVisible();
    await expect(alertNotification).toContainText(/Ingestion Failure|Data Ingestion Error/);
    await expect(alertNotification).toContainText('connection error');
    
    // Verify alert timestamp is recent
    const alertTimestamp = await alertNotification.locator('[data-testid="alert-timestamp"]').textContent();
    expect(alertTimestamp).toBeTruthy();
    
    // Close notification panel
    await page.click('[data-testid="close-notifications"]');
    
    // Navigate to the logs section from the dashboard
    await page.click('[data-testid="view-logs-button"]');
    await page.waitForURL('**/admin/monitoring/logs');
    
    // Verify logs page is loaded
    await expect(page.locator('[data-testid="logs-container"]')).toBeVisible();
    
    // Review logs for the simulated failure event
    const failureLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'connection error' }).first();
    await expect(failureLog).toBeVisible();
    
    // Verify detailed logs available for troubleshooting
    await failureLog.click();
    await expect(page.locator('[data-testid="log-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-level"]')).toHaveText('ERROR');
    await expect(page.locator('[data-testid="log-message"]')).toContainText('connection error');
    await expect(page.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-source"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-stack-trace"]')).toBeVisible();
    
    // Close log details
    await page.click('[data-testid="close-log-details"]');
    
    // Filter logs by failure events only
    await page.click('[data-testid="log-filter-button"]');
    await page.check('[data-testid="filter-error-checkbox"]');
    await page.uncheck('[data-testid="filter-info-checkbox"]');
    await page.uncheck('[data-testid="filter-warning-checkbox"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for filter to apply
    await page.waitForTimeout(1000);
    
    // Verify only error logs are displayed
    const logEntries = page.locator('[data-testid="log-entry"]');
    const logCount = await logEntries.count();
    expect(logCount).toBeGreaterThan(0);
    
    for (let i = 0; i < Math.min(logCount, 5); i++) {
      const logLevel = await logEntries.nth(i).locator('[data-testid="log-entry-level"]').textContent();
      expect(logLevel).toBe('ERROR');
    }
    
    // Navigate back to ingestion health dashboard
    await page.click('[data-testid="back-to-dashboard-button"]');
    await page.waitForURL('**/admin/monitoring/ingestion-health');
    
    // Restore normal data ingestion
    await page.click('[data-testid="simulate-ingestion-button"]');
    await page.selectOption('[data-testid="simulation-type-select"]', 'normal');
    await page.click('[data-testid="start-simulation-button"]');
    
    // Wait for restoration
    await page.waitForTimeout(3000);
    
    // Verify status is back to healthy
    await expect(page.locator('[data-testid="ingestion-status"]')).toHaveText('Healthy', { timeout: 10000 });
    await expect(page.locator('[data-testid="status-indicator"]')).toHaveClass(/healthy|success|green/);
    
    // Verify metrics are updating again
    const restoredRecords = await page.locator('[data-testid="records-processed-metric"]').textContent();
    expect(parseInt(restoredRecords || '0')).toBeGreaterThan(0);
  });

  test('Validate ingestion health dashboard displays accurate status and metrics', async ({ page }) => {
    // Navigate to ingestion health dashboard
    await page.goto('/admin/monitoring/ingestion-health');
    await expect(page.locator('[data-testid="ingestion-dashboard"]')).toBeVisible();
    
    // Action: Simulate normal data ingestion
    await page.click('[data-testid="simulate-ingestion-button"]');
    await page.selectOption('[data-testid="simulation-type-select"]', 'normal');
    await page.click('[data-testid="start-simulation-button"]');
    await page.waitForTimeout(2000);
    
    // Expected Result: Dashboard shows healthy status and metrics
    await expect(page.locator('[data-testid="ingestion-status"]')).toHaveText('Healthy');
    await expect(page.locator('[data-testid="status-indicator"]')).toHaveClass(/healthy|success/);
    await expect(page.locator('[data-testid="ingestion-rate-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="records-processed-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="errors-count-metric"]')).toHaveText('0');
    
    // Action: Simulate ingestion failure
    await page.click('[data-testid="simulate-ingestion-button"]');
    await page.selectOption('[data-testid="simulation-type-select"]', 'failure');
    await page.click('[data-testid="start-simulation-button"]');
    await page.waitForTimeout(3000);
    
    // Expected Result: Dashboard shows failure status and sends alert
    await expect(page.locator('[data-testid="ingestion-status"]')).toHaveText(/Failed|Error/);
    await expect(page.locator('[data-testid="status-indicator"]')).toHaveClass(/failed|error/);
    
    // Verify alert was sent
    await page.click('[data-testid="notifications-icon"]');
    const alert = page.locator('[data-testid="alert-notification"]').first();
    await expect(alert).toBeVisible();
    await expect(alert).toContainText(/Ingestion Failure|Error/);
    await page.click('[data-testid="close-notifications"]');
    
    // Action: Review logs for failure event
    await page.click('[data-testid="view-logs-button"]');
    await page.waitForURL('**/admin/monitoring/logs');
    
    // Expected Result: Detailed logs available for troubleshooting
    const errorLog = page.locator('[data-testid="log-entry"]').filter({ hasText: /ERROR|FAILURE/ }).first();
    await expect(errorLog).toBeVisible();
    
    await errorLog.click();
    await expect(page.locator('[data-testid="log-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-level"]')).toHaveText('ERROR');
    await expect(page.locator('[data-testid="log-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-stack-trace"]')).toBeVisible();
  });

  test('Verify historical ingestion data is available for trend analysis', async ({ page }) => {
    // Navigate to ingestion health dashboard
    await page.goto('/admin/monitoring/ingestion-health');
    
    // Navigate to historical trends section
    await page.click('[data-testid="historical-trends-tab"]');
    
    // Verify historical data visualization is displayed
    await expect(page.locator('[data-testid="trends-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-selector"]')).toBeVisible();
    
    // Select different time ranges
    await page.selectOption('[data-testid="date-range-selector"]', 'last-7-days');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="trends-chart"]')).toBeVisible();
    
    await page.selectOption('[data-testid="date-range-selector"]', 'last-30-days');
    await page.waitForTimeout(1000);
    await expect(page.locator('[data-testid="trends-chart"]')).toBeVisible();
    
    // Verify trend metrics are displayed
    await expect(page.locator('[data-testid="average-ingestion-rate"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-records-processed"]')).toBeVisible();
    await expect(page.locator('[data-testid="failure-rate"]')).toBeVisible();
    await expect(page.locator('[data-testid="uptime-percentage"]')).toBeVisible();
  });
});