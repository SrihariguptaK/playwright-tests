import { test, expect } from '@playwright/test';

test.describe('Story-19: Import Daily Timekeeping Records', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to payroll system
    await page.goto('/payroll/timekeeping-import');
    // Login if needed
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful daily import of timekeeping records', async ({ page }) => {
    // Step 1: Trigger scheduled import job
    await page.click('[data-testid="trigger-import-button"]');
    
    // Wait for import process to start
    await expect(page.locator('[data-testid="import-status"]')).toContainText('In Progress', { timeout: 10000 });
    
    // Expected Result: Timekeeping data is retrieved and imported successfully
    await expect(page.locator('[data-testid="import-status"]')).toContainText('Completed', { timeout: 3600000 });
    
    // Step 2: Verify imported records in payroll system
    await page.click('[data-testid="view-imported-records"]');
    await page.waitForSelector('[data-testid="records-table"]');
    
    // Expected Result: Records reflect latest timekeeping data
    const recordsTable = page.locator('[data-testid="records-table"]');
    await expect(recordsTable).toBeVisible();
    
    const recordCount = await page.locator('[data-testid="record-count"]').textContent();
    expect(parseInt(recordCount || '0')).toBeGreaterThan(0);
    
    // Verify attendance data is present
    await expect(page.locator('[data-testid="attendance-column"]').first()).toBeVisible();
    
    // Verify work hours data is present
    await expect(page.locator('[data-testid="work-hours-column"]').first()).toBeVisible();
    
    // Verify leave data is present
    await expect(page.locator('[data-testid="leave-data-column"]').first()).toBeVisible();
    
    // Step 3: Check import logs
    await page.click('[data-testid="view-import-logs"]');
    await page.waitForSelector('[data-testid="import-logs-table"]');
    
    // Expected Result: No errors logged and completion time within SLA
    const errorCount = await page.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBe(0);
    
    const completionTime = await page.locator('[data-testid="completion-time"]').textContent();
    const completionMinutes = parseInt(completionTime?.match(/\d+/)?.[0] || '0');
    expect(completionMinutes).toBeLessThanOrEqual(60);
    
    const successRate = await page.locator('[data-testid="success-rate"]').textContent();
    const successPercentage = parseFloat(successRate?.replace('%', '') || '0');
    expect(successPercentage).toBeGreaterThanOrEqual(99.9);
    
    await expect(page.locator('[data-testid="import-status-log"]')).toContainText('Success');
  });

  test('Verify handling of incomplete timekeeping data', async ({ page }) => {
    // Step 1: Simulate timekeeping data with missing mandatory fields
    await page.click('[data-testid="test-data-setup"]');
    await page.click('[data-testid="load-incomplete-data"]');
    
    // Select incomplete data scenario
    await page.selectOption('[data-testid="test-scenario-dropdown"]', 'incomplete-mandatory-fields');
    await page.click('[data-testid="apply-test-data"]');
    
    await expect(page.locator('[data-testid="test-data-loaded"]')).toContainText('Incomplete data loaded');
    
    // Trigger import with incomplete data
    await page.click('[data-testid="trigger-import-button"]');
    
    // Wait for import process to complete
    await expect(page.locator('[data-testid="import-status"]')).toContainText('Completed with Errors', { timeout: 3600000 });
    
    // Expected Result: Import logs errors for incomplete records
    await page.click('[data-testid="view-import-logs"]');
    await page.waitForSelector('[data-testid="import-logs-table"]');
    
    const errorLogs = page.locator('[data-testid="error-log-entry"]');
    await expect(errorLogs.first()).toBeVisible();
    
    const errorCount = await errorLogs.count();
    expect(errorCount).toBeGreaterThan(0);
    
    // Verify error messages mention missing mandatory fields
    await expect(errorLogs.first()).toContainText(/missing mandatory field|employee ID|date|work hours/i);
    
    // Step 2: Check that incomplete records are not imported
    await page.click('[data-testid="view-imported-records"]');
    await page.waitForSelector('[data-testid="records-table"]');
    
    // Expected Result: System skips incomplete records and continues processing
    const totalRecordsProcessed = await page.locator('[data-testid="total-records-processed"]').textContent();
    const recordsImported = await page.locator('[data-testid="records-imported"]').textContent();
    const recordsSkipped = await page.locator('[data-testid="records-skipped"]').textContent();
    
    expect(parseInt(recordsSkipped || '0')).toBeGreaterThan(0);
    expect(parseInt(recordsImported || '0')).toBeLessThan(parseInt(totalRecordsProcessed || '0'));
    
    // Verify incomplete records are not in the imported data
    await page.fill('[data-testid="search-records"]', 'INCOMPLETE');
    await page.click('[data-testid="search-button"]');
    
    await expect(page.locator('[data-testid="no-results-message"]')).toBeVisible();
    
    // Verify error notification was sent to payroll team
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="error-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-notification"]')).toContainText('incomplete records');
    
    // Verify error rate is calculated and logged
    const errorRate = await page.locator('[data-testid="error-rate"]').textContent();
    const errorPercentage = parseFloat(errorRate?.replace('%', '') || '0');
    expect(errorPercentage).toBeGreaterThan(0);
    expect(errorPercentage).toBeLessThan(100);
  });
});