import { test, expect } from '@playwright/test';

test.describe('Employee Data Synchronization', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@company.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';
  const HR_API_ENDPOINT = '/api/hr/sync';
  const SYNC_SLA_MINUTES = 30;

  test.beforeEach(async ({ page }) => {
    // Login as HR Manager/Admin
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful daily synchronization of employee data', async ({ page, request }) => {
    // Step 1: Trigger scheduled synchronization job
    await page.goto(`${BASE_URL}/admin/hr-sync`);
    await page.click('[data-testid="trigger-sync-button"]');
    
    // Wait for synchronization to start
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress', { timeout: 10000 });
    
    // Wait for synchronization to complete (within SLA of 30 minutes)
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed', { timeout: SYNC_SLA_MINUTES * 60 * 1000 });
    
    // Verify employee data is retrieved and updated successfully
    const syncResponse = await request.get(`${BASE_URL}${HR_API_ENDPOINT}/status`);
    expect(syncResponse.ok()).toBeTruthy();
    const syncData = await syncResponse.json();
    expect(syncData.status).toBe('completed');
    expect(syncData.recordsProcessed).toBeGreaterThan(0);
    
    // Step 2: Verify updated records in the new platform
    await page.goto(`${BASE_URL}/admin/employees`);
    await page.waitForSelector('[data-testid="employee-table"]');
    
    // Get employee count from table
    const employeeRows = await page.locator('[data-testid="employee-row"]').count();
    expect(employeeRows).toBeGreaterThan(0);
    
    // Verify a sample employee record reflects latest HR system data
    const firstEmployee = page.locator('[data-testid="employee-row"]').first();
    await expect(firstEmployee).toBeVisible();
    await expect(firstEmployee.locator('[data-testid="employee-id"]')).not.toBeEmpty();
    await expect(firstEmployee.locator('[data-testid="employee-name"]')).not.toBeEmpty();
    await expect(firstEmployee.locator('[data-testid="employee-email"]')).not.toBeEmpty();
    
    // Step 3: Check synchronization logs
    await page.goto(`${BASE_URL}/admin/hr-sync/logs`);
    await page.waitForSelector('[data-testid="sync-logs-table"]');
    
    // Get the latest log entry
    const latestLog = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLog.locator('[data-testid="log-status"]')).toContainText('Success');
    
    // Verify no errors logged
    const errorCount = await latestLog.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBe(0);
    
    // Verify completion time within SLA
    const completionTime = await latestLog.locator('[data-testid="completion-time"]').textContent();
    expect(completionTime).toBeTruthy();
    
    const duration = await latestLog.locator('[data-testid="sync-duration"]').textContent();
    const durationMinutes = parseInt(duration?.replace(/[^0-9]/g, '') || '0');
    expect(durationMinutes).toBeLessThanOrEqual(SYNC_SLA_MINUTES);
    
    // Verify total count of records processed matches
    const processedCount = await latestLog.locator('[data-testid="records-processed"]').textContent();
    expect(parseInt(processedCount || '0')).toBe(syncData.recordsProcessed);
  });

  test('Verify handling of incomplete employee data', async ({ page, request }) => {
    // Step 1: Simulate employee data with missing mandatory fields
    // This would typically be done by setting up test data in the HR system
    // For automation, we'll trigger sync and verify error handling
    
    // Prepare test scenario with incomplete data flag (if API supports test mode)
    const testDataPayload = {
      testMode: true,
      includeIncompleteRecords: true,
      incompleteRecords: [
        { id: 'TEST001', firstName: 'John' }, // Missing lastName, email
        { id: 'TEST002', lastName: 'Doe' }, // Missing firstName, email
        { id: 'TEST003', firstName: 'Jane', lastName: 'Smith' } // Missing email
      ],
      validRecords: [
        { id: 'TEST004', firstName: 'Valid', lastName: 'Employee', email: 'valid@company.com' }
      ]
    };
    
    // Trigger synchronization job with test data
    await page.goto(`${BASE_URL}/admin/hr-sync`);
    
    // Enable test mode if available
    const testModeToggle = page.locator('[data-testid="test-mode-toggle"]');
    if (await testModeToggle.isVisible()) {
      await testModeToggle.check();
    }
    
    await page.click('[data-testid="trigger-sync-button"]');
    
    // Wait for synchronization to complete
    await expect(page.locator('[data-testid="sync-status"]')).toContainText(/Completed|Partial Success/, { timeout: SYNC_SLA_MINUTES * 60 * 1000 });
    
    // Step 2: Access synchronization logs and search for error entries
    await page.goto(`${BASE_URL}/admin/hr-sync/logs`);
    await page.waitForSelector('[data-testid="sync-logs-table"]');
    
    const latestLog = page.locator('[data-testid="log-entry"]').first();
    
    // Verify synchronization logs errors for incomplete records
    const errorCount = await latestLog.locator('[data-testid="error-count"]').textContent();
    expect(parseInt(errorCount || '0')).toBeGreaterThan(0);
    
    // Click to view error details
    await latestLog.locator('[data-testid="view-errors-button"]').click();
    await page.waitForSelector('[data-testid="error-details-modal"]');
    
    // Verify error messages mention missing mandatory fields
    const errorMessages = page.locator('[data-testid="error-message"]');
    const errorCount_actual = await errorMessages.count();
    expect(errorCount_actual).toBeGreaterThan(0);
    
    // Check for specific validation errors
    await expect(errorMessages.first()).toContainText(/missing mandatory field|required field|incomplete/i);
    
    await page.locator('[data-testid="close-modal-button"]').click();
    
    // Step 3: Verify incomplete records are not updated in the platform
    await page.goto(`${BASE_URL}/admin/employees`);
    await page.waitForSelector('[data-testid="employee-table"]');
    
    // Search for incomplete test records by ID
    const searchInput = page.locator('[data-testid="employee-search-input"]');
    await searchInput.fill('TEST001');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    // Verify incomplete record is not in the system
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();
    
    // Verify valid record was processed successfully
    await searchInput.clear();
    await searchInput.fill('TEST004');
    await page.click('[data-testid="search-button"]');
    await page.waitForTimeout(1000);
    
    const validEmployeeRow = page.locator('[data-testid="employee-row"]').first();
    await expect(validEmployeeRow).toBeVisible();
    await expect(validEmployeeRow.locator('[data-testid="employee-id"]')).toContainText('TEST004');
    await expect(validEmployeeRow.locator('[data-testid="employee-name"]')).toContainText('Valid Employee');
    
    // Step 4: Verify synchronization continues processing remaining valid records
    const processedCount = await latestLog.locator('[data-testid="records-processed"]').textContent();
    const successCount = await latestLog.locator('[data-testid="success-count"]').textContent();
    
    expect(parseInt(successCount || '0')).toBeGreaterThan(0);
    expect(parseInt(processedCount || '0')).toBeGreaterThan(parseInt(successCount || '0'));
    
    // Step 5: Verify error notification is sent to HR team
    await page.goto(`${BASE_URL}/admin/notifications`);
    await page.waitForSelector('[data-testid="notifications-list"]');
    
    const syncErrorNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: /sync.*error|incomplete.*employee/i }).first();
    await expect(syncErrorNotification).toBeVisible();
    await expect(syncErrorNotification).toContainText(/incomplete records|validation error/i);
    
    // Step 6: Confirm synchronization job completes with partial success status
    await page.goto(`${BASE_URL}/admin/hr-sync/logs`);
    const finalStatus = await page.locator('[data-testid="log-entry"]').first().locator('[data-testid="log-status"]').textContent();
    expect(finalStatus).toMatch(/Partial Success|Completed with Errors/i);
  });
});