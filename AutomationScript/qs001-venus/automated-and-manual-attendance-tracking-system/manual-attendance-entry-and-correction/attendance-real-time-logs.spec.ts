import { test, expect } from '@playwright/test';

test.describe('Story-28: Real-time Attendance Logs for Attendance Officer', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ATTENDANCE_OFFICER_USERNAME = 'attendance.officer@company.com';
  const ATTENDANCE_OFFICER_PASSWORD = 'AttendanceOfficer123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate real-time attendance log display and filtering', async ({ page }) => {
    // Step 1: Login as attendance officer
    await page.fill('[data-testid="username-input"]', ATTENDANCE_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', ATTENDANCE_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to attendance log dashboard
    await expect(page).toHaveURL(/.*\/attendance\/dashboard/);
    await expect(page.locator('[data-testid="attendance-log-dashboard"]')).toBeVisible();
    
    // Step 2: View attendance logs with default filters
    await page.waitForSelector('[data-testid="attendance-logs-table"]', { timeout: 10000 });
    
    // Expected Result: Logs displayed with recent validated records
    const logsTable = page.locator('[data-testid="attendance-logs-table"]');
    await expect(logsTable).toBeVisible();
    
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    const rowCount = await logRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Verify only validated records are displayed
    const validatedBadges = page.locator('[data-testid="status-badge"][data-status="validated"]');
    const validatedCount = await validatedBadges.count();
    expect(validatedCount).toBe(rowCount);
    
    // Step 3: Apply employee and date filters
    // Locate and click on the employee filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.waitForSelector('[data-testid="employee-filter-options"]');
    
    // Select a specific employee from the dropdown list
    await page.click('[data-testid="employee-option"]:first-child');
    const selectedEmployeeName = await page.locator('[data-testid="employee-filter-dropdown"]').textContent();
    
    // Observe the filtered attendance logs
    await page.waitForTimeout(1000); // Wait for filter to apply
    const filteredByEmployeeRows = page.locator('[data-testid="attendance-log-row"]');
    const filteredEmployeeCount = await filteredByEmployeeRows.count();
    
    // Verify employee filter is applied
    if (filteredEmployeeCount > 0) {
      const firstRowEmployee = await page.locator('[data-testid="attendance-log-row"]:first-child [data-testid="employee-name"]').textContent();
      expect(firstRowEmployee).toContain(selectedEmployeeName?.trim() || '');
    }
    
    // Locate and click on the date filter field
    await page.click('[data-testid="date-filter-input"]');
    await page.waitForSelector('[data-testid="date-picker"]');
    
    // Select a specific date from the date picker
    const today = new Date();
    const dateString = today.toISOString().split('T')[0];
    await page.fill('[data-testid="date-filter-input"]', dateString);
    await page.keyboard.press('Enter');
    
    // Expected Result: Logs filtered accordingly
    await page.waitForTimeout(1000); // Wait for filter to apply
    const filteredByDateRows = page.locator('[data-testid="attendance-log-row"]');
    const filteredDateCount = await filteredByDateRows.count();
    
    // Verify filters are applied and record count is updated
    const recordCountDisplay = page.locator('[data-testid="record-count"]');
    await expect(recordCountDisplay).toBeVisible();
    const displayedCount = await recordCountDisplay.textContent();
    expect(displayedCount).toContain(filteredDateCount.toString());
    
    // Locate and click on the status filter dropdown
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.waitForSelector('[data-testid="status-filter-options"]');
    
    // Select a specific status from the dropdown
    await page.click('[data-testid="status-option-validated"]');
    
    // Observe the filtered attendance logs with all three filters applied
    await page.waitForTimeout(1000); // Wait for filter to apply
    const finalFilteredRows = page.locator('[data-testid="attendance-log-row"]');
    const finalCount = await finalFilteredRows.count();
    
    // Verify the record count updates to reflect filtered results
    const finalRecordCount = await page.locator('[data-testid="record-count"]').textContent();
    expect(finalRecordCount).toContain(finalCount.toString());
  });

  test('Verify automatic data refresh functionality', async ({ page }) => {
    // Login as attendance officer
    await page.fill('[data-testid="username-input"]', ATTENDANCE_OFFICER_USERNAME);
    await page.fill('[data-testid="password-input"]', ATTENDANCE_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/.*\/attendance\/dashboard/);
    await page.waitForSelector('[data-testid="attendance-logs-table"]', { timeout: 10000 });
    
    // Note the current timestamp displayed on the dashboard
    const initialTimestamp = await page.locator('[data-testid="last-refresh-timestamp"]').textContent();
    
    // Note the current number of attendance records displayed
    const initialRecordCount = await page.locator('[data-testid="attendance-log-row"]').count();
    const initialCountDisplay = await page.locator('[data-testid="record-count"]').textContent();
    
    // Observe the attendance log dashboard without any user interaction
    // Wait for 1 minute while monitoring the dashboard
    await page.waitForTimeout(60000); // Wait for 1 minute
    
    // Expected Result: Data refreshes automatically every minute
    // Verify the timestamp updates to reflect the automatic refresh
    const firstRefreshTimestamp = await page.locator('[data-testid="last-refresh-timestamp"]').textContent();
    expect(firstRefreshTimestamp).not.toBe(initialTimestamp);
    
    // Check if any new attendance records appear in the log
    const firstRefreshRecordCount = await page.locator('[data-testid="attendance-log-row"]').count();
    
    // Verify the refresh completes within 5 seconds as per performance requirements
    const refreshStartTime = Date.now();
    await page.click('[data-testid="manual-refresh-button"]');
    await page.waitForSelector('[data-testid="refresh-indicator"]', { state: 'hidden', timeout: 5000 });
    const refreshDuration = Date.now() - refreshStartTime;
    expect(refreshDuration).toBeLessThan(5000);
    
    // Continue observing the dashboard for an additional 1 minute without interaction
    const secondRefreshTimestamp = await page.locator('[data-testid="last-refresh-timestamp"]').textContent();
    
    // Wait for the second automatic refresh cycle to complete
    await page.waitForTimeout(60000); // Wait for another 1 minute
    
    // Verify the timestamp updates again to reflect the second automatic refresh
    const thirdRefreshTimestamp = await page.locator('[data-testid="last-refresh-timestamp"]').textContent();
    expect(thirdRefreshTimestamp).not.toBe(secondRefreshTimestamp);
    
    // Check for any additional new attendance records in the log
    const secondRefreshRecordCount = await page.locator('[data-testid="attendance-log-row"]').count();
    
    // Verify no error messages or warnings appear during automatic refresh cycles
    const errorMessages = page.locator('[data-testid="error-message"]');
    await expect(errorMessages).toHaveCount(0);
    
    const warningMessages = page.locator('[data-testid="warning-message"]');
    await expect(warningMessages).toHaveCount(0);
    
    // Confirm data freshness is maintained at 99% within 1 minute as per success metrics
    const dataFreshnessIndicator = page.locator('[data-testid="data-freshness-indicator"]');
    await expect(dataFreshnessIndicator).toBeVisible();
    const freshnessText = await dataFreshnessIndicator.textContent();
    expect(freshnessText).toMatch(/99%|100%/);
  });
});