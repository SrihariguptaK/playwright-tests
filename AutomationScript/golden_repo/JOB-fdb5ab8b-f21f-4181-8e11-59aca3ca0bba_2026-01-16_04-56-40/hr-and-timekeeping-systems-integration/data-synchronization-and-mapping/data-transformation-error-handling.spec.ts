import { test, expect } from '@playwright/test';

test.describe('Data Transformation Error Handling', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'Admin123!';

  test.beforeEach(async ({ page }) => {
    // Login as administrator
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify detection and logging of transformation errors (happy-path)', async ({ page }) => {
    // Prepare test data containing records with known transformation errors
    await page.goto(`${BASE_URL}/data-management/test-data`);
    await page.click('[data-testid="create-test-dataset-button"]');
    
    // Add records with invalid data types
    await page.fill('[data-testid="dataset-name-input"]', 'ErrorProneDataset_' + Date.now());
    await page.click('[data-testid="add-invalid-datatype-record"]');
    await page.fill('[data-testid="record-field-age"]', 'invalid_age_string');
    
    // Add records with missing required fields
    await page.click('[data-testid="add-missing-field-record"]');
    await page.fill('[data-testid="record-field-name"]', 'Test User');
    // Intentionally skip required email field
    
    // Add records with format violations
    await page.click('[data-testid="add-format-violation-record"]');
    await page.fill('[data-testid="record-field-email"]', 'invalid-email-format');
    
    await page.click('[data-testid="save-test-dataset-button"]');
    await expect(page.locator('[data-testid="dataset-saved-message"]')).toBeVisible();
    
    // Load the test dataset into the source system for synchronization
    const datasetName = await page.locator('[data-testid="dataset-name"]').first().textContent();
    await page.click('[data-testid="load-to-source-button"]');
    await expect(page.locator('[data-testid="dataset-loaded-message"]')).toBeVisible();
    
    // Navigate to the synchronization dashboard
    await page.goto(`${BASE_URL}/sync/dashboard`);
    await expect(page.locator('[data-testid="sync-dashboard-title"]')).toBeVisible();
    
    // Initiate synchronization process for the test dataset
    await page.click('[data-testid="new-sync-button"]');
    await page.selectOption('[data-testid="dataset-selector"]', { label: datasetName });
    await page.click('[data-testid="start-sync-button"]');
    
    // Monitor the synchronization process as it encounters transformation errors
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Running', { timeout: 10000 });
    await expect(page.locator('[data-testid="errors-detected-indicator"]')).toBeVisible({ timeout: 30000 });
    
    // Wait for synchronization process to complete
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 60000 });
    const syncStatus = await page.locator('[data-testid="sync-status"]').textContent();
    expect(syncStatus).toContain('Completed');
    
    // Navigate to error logs section via /sync/errors endpoint
    await page.goto(`${BASE_URL}/sync/errors`);
    await expect(page.locator('[data-testid="error-logs-title"]')).toBeVisible();
    
    // Review error log entries for the completed synchronization job
    const errorLogEntries = page.locator('[data-testid="error-log-entry"]');
    await expect(errorLogEntries).not.toHaveCount(0);
    
    // Verify errors are logged with detailed context
    const firstError = errorLogEntries.first();
    await expect(firstError.locator('[data-testid="error-timestamp"]')).toBeVisible();
    await expect(firstError.locator('[data-testid="error-record-id"]')).toBeVisible();
    await expect(firstError.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(firstError.locator('[data-testid="error-context"]')).toBeVisible();
    
    // Verify error classification in the logs
    const errorTypes = await page.locator('[data-testid="error-type"]').allTextContents();
    expect(errorTypes).toContain('INVALID_DATA_TYPE');
    expect(errorTypes).toContain('MISSING_REQUIRED_FIELD');
    expect(errorTypes).toContain('FORMAT_VIOLATION');
    
    // Access error reports and verify accessibility
    await page.click('[data-testid="generate-error-report-button"]');
    await expect(page.locator('[data-testid="error-report-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-details-table"]')).toBeVisible();
  });

  test('Test notification delivery upon error detection (happy-path)', async ({ page }) => {
    // Configure notification settings to ensure administrators are subscribed
    await page.goto(`${BASE_URL}/settings/notifications`);
    await expect(page.locator('[data-testid="notification-settings-title"]')).toBeVisible();
    
    const errorNotificationToggle = page.locator('[data-testid="error-notification-toggle"]');
    const isEnabled = await errorNotificationToggle.isChecked();
    if (!isEnabled) {
      await errorNotificationToggle.check();
    }
    
    await page.fill('[data-testid="notification-email-input"]', ADMIN_EMAIL);
    await page.click('[data-testid="save-notification-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Prepare and load test dataset containing multiple records with transformation errors
    await page.goto(`${BASE_URL}/data-management/test-data`);
    await page.click('[data-testid="create-test-dataset-button"]');
    
    const datasetName = 'ErrorNotificationTest_' + Date.now();
    await page.fill('[data-testid="dataset-name-input"]', datasetName);
    
    // Add multiple error records
    for (let i = 0; i < 5; i++) {
      await page.click('[data-testid="add-error-record-button"]');
      await page.fill(`[data-testid="record-${i}-field-id"]`, `error_record_${i}`);
      await page.fill(`[data-testid="record-${i}-field-value"]`, 'invalid_value');
    }
    
    await page.click('[data-testid="save-test-dataset-button"]');
    await page.click('[data-testid="load-to-source-button"]');
    
    // Initiate synchronization process with the error-prone dataset
    await page.goto(`${BASE_URL}/sync/dashboard`);
    await page.click('[data-testid="new-sync-button"]');
    await page.selectOption('[data-testid="dataset-selector"]', { label: datasetName });
    
    const syncStartTime = Date.now();
    await page.click('[data-testid="start-sync-button"]');
    
    // Monitor system as transformation errors are detected
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Running', { timeout: 10000 });
    await expect(page.locator('[data-testid="errors-detected-indicator"]')).toBeVisible({ timeout: 30000 });
    
    // Check notification delivery
    await page.goto(`${BASE_URL}/notifications`);
    await page.waitForTimeout(5000); // Allow time for notification to be sent
    
    const notifications = page.locator('[data-testid="notification-item"]');
    await expect(notifications.first()).toBeVisible({ timeout: 10000 });
    
    // Check notification delivery time
    const notificationTime = await page.locator('[data-testid="notification-timestamp"]').first().textContent();
    const notificationTimestamp = new Date(notificationTime).getTime();
    const deliveryTime = notificationTimestamp - syncStartTime;
    expect(deliveryTime).toBeLessThan(60000); // Should be delivered within 60 seconds
    
    // Verify notification recipients list
    await notifications.first().click();
    await expect(page.locator('[data-testid="notification-details-modal"]')).toBeVisible();
    const recipients = await page.locator('[data-testid="notification-recipient"]').allTextContents();
    expect(recipients).toContain(ADMIN_EMAIL);
    
    // Open and review notification content
    const notificationTitle = await page.locator('[data-testid="notification-title"]').textContent();
    expect(notificationTitle).toContain('Transformation Error');
    
    const notificationBody = await page.locator('[data-testid="notification-body"]').textContent();
    expect(notificationBody).toContain('error');
    expect(notificationBody).toContain('synchronization');
    
    // Verify notification contains error summary
    await expect(page.locator('[data-testid="error-summary-section"]')).toBeVisible();
    const errorCount = await page.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount)).toBeGreaterThan(0);
    
    // Click on the link to detailed error logs
    await page.click('[data-testid="view-error-logs-link"]');
    await expect(page).toHaveURL(/.*\/sync\/errors/);
    await expect(page.locator('[data-testid="error-logs-title"]')).toBeVisible();
    
    // Verify notification format and readability
    await page.goto(`${BASE_URL}/notifications`);
    await notifications.first().click();
    const notificationContent = page.locator('[data-testid="notification-content"]');
    await expect(notificationContent).toBeVisible();
    const fontSize = await notificationContent.evaluate(el => window.getComputedStyle(el).fontSize);
    expect(parseInt(fontSize)).toBeGreaterThanOrEqual(12);
  });

  test('Validate synchronization performance with errors (boundary)', async ({ page }) => {
    // Review and document the SLA performance limits
    await page.goto(`${BASE_URL}/settings/sla`);
    await expect(page.locator('[data-testid="sla-settings-title"]')).toBeVisible();
    
    const slaLimit = await page.locator('[data-testid="sync-duration-sla"]').textContent();
    const slaLimitSeconds = parseInt(slaLimit);
    expect(slaLimitSeconds).toBeGreaterThan(0);
    
    // Prepare test dataset containing 10,000 records with 20% containing transformation errors
    await page.goto(`${BASE_URL}/data-management/test-data`);
    await page.click('[data-testid="create-bulk-dataset-button"]');
    
    const performanceDatasetName = 'PerformanceTest_' + Date.now();
    await page.fill('[data-testid="dataset-name-input"]', performanceDatasetName);
    await page.fill('[data-testid="total-records-input"]', '10000');
    await page.fill('[data-testid="error-percentage-input"]', '20');
    await page.click('[data-testid="generate-dataset-button"]');
    
    await expect(page.locator('[data-testid="dataset-generation-complete"]')).toBeVisible({ timeout: 120000 });
    
    // Record baseline synchronization time with valid records
    await page.click('[data-testid="create-bulk-dataset-button"]');
    const baselineDatasetName = 'BaselineTest_' + Date.now();
    await page.fill('[data-testid="dataset-name-input"]', baselineDatasetName);
    await page.fill('[data-testid="total-records-input"]', '10000');
    await page.fill('[data-testid="error-percentage-input"]', '0');
    await page.click('[data-testid="generate-dataset-button"]');
    await expect(page.locator('[data-testid="dataset-generation-complete"]')).toBeVisible({ timeout: 120000 });
    
    await page.click('[data-testid="load-to-source-button"]');
    await expect(page.locator('[data-testid="dataset-loaded-message"]')).toBeVisible();
    
    await page.goto(`${BASE_URL}/sync/dashboard`);
    await page.click('[data-testid="new-sync-button"]');
    await page.selectOption('[data-testid="dataset-selector"]', { label: baselineDatasetName });
    
    const baselineStartTime = Date.now();
    await page.click('[data-testid="start-sync-button"]');
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 300000 });
    const baselineEndTime = Date.now();
    const baselineDuration = (baselineEndTime - baselineStartTime) / 1000;
    
    // Clear cached data and reset system
    await page.goto(`${BASE_URL}/admin/system`);
    await page.click('[data-testid="clear-cache-button"]');
    await expect(page.locator('[data-testid="cache-cleared-message"]')).toBeVisible();
    await page.click('[data-testid="reset-system-button"]');
    await expect(page.locator('[data-testid="system-reset-message"]')).toBeVisible();
    
    // Start performance monitoring
    await page.goto(`${BASE_URL}/monitoring/performance`);
    await page.click('[data-testid="start-monitoring-button"]');
    await expect(page.locator('[data-testid="monitoring-active-indicator"]')).toBeVisible();
    
    // Initiate synchronization with error-prone dataset
    await page.goto(`${BASE_URL}/sync/dashboard`);
    await page.click('[data-testid="new-sync-button"]');
    await page.selectOption('[data-testid="dataset-selector"]', { label: performanceDatasetName });
    
    const performanceStartTime = Date.now();
    await page.click('[data-testid="start-sync-button"]');
    
    // Monitor synchronization progress
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Running', { timeout: 10000 });
    await expect(page.locator('[data-testid="sync-progress-bar"]')).toBeVisible();
    
    // Observe error handling overhead
    await expect(page.locator('[data-testid="errors-detected-count"]')).toBeVisible({ timeout: 30000 });
    const errorsDetected = await page.locator('[data-testid="errors-detected-count"]').textContent();
    expect(parseInt(errorsDetected)).toBeGreaterThan(0);
    
    // Wait for synchronization to complete
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 300000 });
    const performanceEndTime = Date.now();
    
    // Calculate total synchronization duration
    const performanceDuration = (performanceEndTime - performanceStartTime) / 1000;
    
    // Compare against SLA limits
    expect(performanceDuration).toBeLessThanOrEqual(slaLimitSeconds);
    
    // Review performance metrics
    await page.goto(`${BASE_URL}/monitoring/performance`);
    await page.click('[data-testid="stop-monitoring-button"]');
    
    const cpuUsage = await page.locator('[data-testid="avg-cpu-usage"]').textContent();
    const memoryUsage = await page.locator('[data-testid="avg-memory-usage"]').textContent();
    const ioUsage = await page.locator('[data-testid="avg-io-usage"]').textContent();
    
    expect(parseFloat(cpuUsage)).toBeLessThan(90);
    expect(parseFloat(memoryUsage)).toBeLessThan(90);
    expect(parseFloat(ioUsage)).toBeLessThan(90);
    
    // Verify valid records processed at expected throughput
    const validRecordsProcessed = await page.locator('[data-testid="valid-records-count"]').textContent();
    expect(parseInt(validRecordsProcessed)).toBe(8000); // 80% of 10,000
    
    const throughput = parseInt(validRecordsProcessed) / performanceDuration;
    const expectedThroughput = 8000 / slaLimitSeconds;
    expect(throughput).toBeGreaterThanOrEqual(expectedThroughput * 0.9); // Allow 10% variance
    
    // Review error logging overhead impact
    const errorLoggingOverhead = performanceDuration - baselineDuration;
    const overheadPercentage = (errorLoggingOverhead / baselineDuration) * 100;
    expect(overheadPercentage).toBeLessThan(20); // Error handling should add less than 20% overhead
  });
});