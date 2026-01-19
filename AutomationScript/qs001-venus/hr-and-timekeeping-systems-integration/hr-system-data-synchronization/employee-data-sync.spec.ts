import { test, expect } from '@playwright/test';

test.describe('Story-16: Employee Personal Data Synchronization', () => {
  const BASE_URL = process.env.BASE_URL || 'https://hr-platform.example.com';
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.hr-platform.example.com';
  
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful daily synchronization of employee data', async ({ page, request }) => {
    // Step 1: Trigger scheduled synchronization job
    await page.goto(`${BASE_URL}/hr/synchronization`);
    await page.click('[data-testid="trigger-sync-button"]');
    
    // Wait for synchronization to start
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 10000 });
    
    // Expected Result: Employee data is retrieved and updated successfully
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 1800000 }); // 30 min timeout
    
    // Step 2: Verify updated records in the new platform
    await page.goto(`${BASE_URL}/hr/employees`);
    await page.waitForSelector('[data-testid="employee-list"]');
    
    // Check sample employee records
    const employeeRow = page.locator('[data-testid="employee-row"]').first();
    await expect(employeeRow).toBeVisible();
    
    // Verify employee data fields are populated
    await expect(employeeRow.locator('[data-testid="employee-id"]')).not.toBeEmpty();
    await expect(employeeRow.locator('[data-testid="employee-name"]')).not.toBeEmpty();
    await expect(employeeRow.locator('[data-testid="employee-email"]')).not.toBeEmpty();
    
    // Expected Result: Employee records reflect latest HR system data
    const lastSyncTime = await page.locator('[data-testid="last-sync-timestamp"]').textContent();
    expect(lastSyncTime).toBeTruthy();
    
    // Step 3: Check synchronization logs
    await page.goto(`${BASE_URL}/hr/synchronization/logs`);
    await page.waitForSelector('[data-testid="sync-logs-table"]');
    
    // Get the latest log entry
    const latestLog = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLog.locator('[data-testid="log-status"]')).toContainText('Success');
    
    // Expected Result: No errors logged and completion time within SLA
    const errorCount = await latestLog.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBe(0);
    
    const completionTime = await latestLog.locator('[data-testid="completion-time"]').textContent();
    const completionMinutes = parseInt(completionTime?.match(/\d+/)?.[0] || '0');
    expect(completionMinutes).toBeLessThanOrEqual(30);
    
    // Verify synchronization summary
    const recordsProcessed = await page.locator('[data-testid="records-processed"]').textContent();
    const recordsUpdated = await page.locator('[data-testid="records-updated"]').textContent();
    expect(parseInt(recordsProcessed || '0')).toBeGreaterThan(0);
    expect(parseInt(recordsUpdated || '0')).toBeGreaterThan(0);
  });

  test('Verify handling of incomplete employee data', async ({ page, request }) => {
    // Step 1: Simulate employee data with missing mandatory fields
    // Navigate to test data preparation page or use API to inject test data
    await page.goto(`${BASE_URL}/hr/test-data`);
    
    // Create test employee with missing mandatory fields
    await page.click('[data-testid="add-test-employee-button"]');
    await page.fill('[data-testid="employee-id-input"]', 'TEST001');
    // Intentionally leave first name empty
    await page.fill('[data-testid="last-name-input"]', '');
    await page.fill('[data-testid="email-input"]', '');
    await page.click('[data-testid="save-test-employee-button"]');
    
    await expect(page.locator('[data-testid="test-employee-created"]')).toBeVisible();
    
    // Trigger synchronization job
    await page.goto(`${BASE_URL}/hr/synchronization`);
    await page.click('[data-testid="trigger-sync-button"]');
    
    // Wait for synchronization to complete
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: 1800000 });
    
    // Expected Result: Synchronization logs errors for incomplete records
    await page.goto(`${BASE_URL}/hr/synchronization/logs`);
    await page.waitForSelector('[data-testid="sync-logs-table"]');
    
    const latestLog = page.locator('[data-testid="log-entry"]').first();
    await latestLog.click();
    
    // Check for error entries
    await expect(page.locator('[data-testid="error-section"]')).toBeVisible();
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toContainText(/missing mandatory field/i);
    
    const errorCount = await latestLog.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBeGreaterThan(0);
    
    // Step 2: Check that incomplete records are not updated
    await page.goto(`${BASE_URL}/hr/employees`);
    await page.fill('[data-testid="search-employee-input"]', 'TEST001');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: System skips incomplete records and continues processing
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();
    await expect(noResultsMessage).toContainText(/no employees found/i);
    
    // Verify that synchronization continued processing other records
    await page.goto(`${BASE_URL}/hr/synchronization/logs`);
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    
    const recordsProcessed = await latestLogEntry.locator('[data-testid="records-processed"]').textContent();
    const recordsSkipped = await latestLogEntry.locator('[data-testid="records-skipped"]').textContent();
    const recordsUpdated = await latestLogEntry.locator('[data-testid="records-updated"]').textContent();
    
    expect(parseInt(recordsProcessed || '0')).toBeGreaterThan(0);
    expect(parseInt(recordsSkipped || '0')).toBeGreaterThan(0);
    expect(parseInt(recordsUpdated || '0')).toBeGreaterThan(0);
    
    // Verify error notifications sent to HR team
    await page.goto(`${BASE_URL}/notifications`);
    const errorNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: /synchronization error/i }).first();
    await expect(errorNotification).toBeVisible();
    await expect(errorNotification).toContainText(/incomplete employee data/i);
  });
});