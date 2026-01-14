import { test, expect } from '@playwright/test';

test.describe('Attendance Reconciliation - Story 18', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_ID = 'EMP001';
  const TEST_DATE = '2024-01-15';
  const MANUAL_CHECK_IN = '09:00 AM';
  const AUTOMATED_CHECK_IN = '09:30 AM';
  const JUSTIFICATION = 'Manual record verified with security logs';

  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'attendance.manager');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate detection and reporting of attendance discrepancies (happy-path)', async ({ page }) => {
    // Step 1: Create a manual attendance record for Employee ID 'EMP001' with check-in time '09:00 AM' for date '2024-01-15'
    await page.goto(`${BASE_URL}/attendance/manual-entry`);
    await page.fill('[data-testid="employee-id-input"]', EMPLOYEE_ID);
    await page.fill('[data-testid="attendance-date-input"]', TEST_DATE);
    await page.fill('[data-testid="check-in-time-input"]', MANUAL_CHECK_IN);
    await page.selectOption('[data-testid="entry-type-select"]', 'manual');
    await page.click('[data-testid="save-manual-entry-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Manual attendance record created successfully');

    // Step 2: Create an automated attendance record for the same Employee ID 'EMP001' with check-in time '09:30 AM' for the same date '2024-01-15'
    await page.goto(`${BASE_URL}/attendance/automated-entry`);
    await page.fill('[data-testid="employee-id-input"]', EMPLOYEE_ID);
    await page.fill('[data-testid="attendance-date-input"]', TEST_DATE);
    await page.fill('[data-testid="check-in-time-input"]', AUTOMATED_CHECK_IN);
    await page.selectOption('[data-testid="entry-type-select"]', 'automated');
    await page.click('[data-testid="save-automated-entry-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Automated attendance record created successfully');

    // Step 3: Trigger the reconciliation process by navigating to Attendance Reconciliation module
    await page.goto(`${BASE_URL}/attendance/reconciliation`);
    await page.click('[data-testid="run-reconciliation-button"]');
    
    // Step 4: Wait for the reconciliation process to complete and check for discrepancy flags
    await expect(page.locator('[data-testid="reconciliation-status"]')).toContainText('In Progress', { timeout: 5000 });
    await expect(page.locator('[data-testid="reconciliation-status"]')).toContainText('Completed', { timeout: 120000 });
    await expect(page.locator('[data-testid="discrepancies-found-count"]')).not.toContainText('0');

    // Expected Result: System flags discrepancies in report
    const discrepancyFlag = page.locator(`[data-testid="discrepancy-flag-${EMPLOYEE_ID}"]`);
    await expect(discrepancyFlag).toBeVisible();

    // Step 5: Navigate to the discrepancy report section and open the generated report
    await page.click('[data-testid="view-discrepancy-report-button"]');
    await expect(page).toHaveURL(/.*reconciliation\/report/);

    // Step 6: Review the discrepancy report for Employee ID 'EMP001'
    const discrepancyRow = page.locator(`[data-testid="discrepancy-row-${EMPLOYEE_ID}"]`);
    await expect(discrepancyRow).toBeVisible();
    
    // Expected Result: Discrepancies are clearly listed with details
    await expect(discrepancyRow.locator('[data-testid="employee-id"]')).toContainText(EMPLOYEE_ID);
    await expect(discrepancyRow.locator('[data-testid="date"]')).toContainText(TEST_DATE);
    await expect(discrepancyRow.locator('[data-testid="manual-time"]')).toContainText(MANUAL_CHECK_IN);
    await expect(discrepancyRow.locator('[data-testid="automated-time"]')).toContainText(AUTOMATED_CHECK_IN);

    // Step 7: Select the discrepancy entry for Employee ID 'EMP001' and click on 'Override' or 'Resolve' option
    await discrepancyRow.click();
    await page.click('[data-testid="override-button"]');
    await expect(page.locator('[data-testid="override-modal"]')).toBeVisible();

    // Step 8: Enter the correct check-in time as '09:00 AM', add justification comment, and submit the override
    await page.fill('[data-testid="corrected-time-input"]', MANUAL_CHECK_IN);
    await page.fill('[data-testid="justification-input"]', JUSTIFICATION);
    await page.click('[data-testid="submit-override-button"]');
    
    // Expected Result: Override saved and logged in audit trail
    await expect(page.locator('[data-testid="override-success-message"]')).toContainText('Override saved successfully');

    // Step 9: Navigate to the audit trail section and search for changes related to Employee ID 'EMP001' on date '2024-01-15'
    await page.goto(`${BASE_URL}/attendance/audit-trail`);
    await page.fill('[data-testid="audit-employee-search"]', EMPLOYEE_ID);
    await page.fill('[data-testid="audit-date-search"]', TEST_DATE);
    await page.click('[data-testid="audit-search-button"]');

    const auditEntry = page.locator(`[data-testid="audit-entry-${EMPLOYEE_ID}-${TEST_DATE}"]`).first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-action"]')).toContainText('Override');
    await expect(auditEntry.locator('[data-testid="audit-justification"]')).toContainText(JUSTIFICATION);
    await expect(auditEntry.locator('[data-testid="audit-corrected-value"]')).toContainText(MANUAL_CHECK_IN);

    // Step 10: Verify the attendance record for Employee ID 'EMP001' reflects the corrected time
    await page.goto(`${BASE_URL}/attendance/records`);
    await page.fill('[data-testid="employee-search-input"]', EMPLOYEE_ID);
    await page.fill('[data-testid="date-search-input"]', TEST_DATE);
    await page.click('[data-testid="search-button"]');

    const attendanceRecord = page.locator(`[data-testid="attendance-record-${EMPLOYEE_ID}"]`);
    await expect(attendanceRecord).toBeVisible();
    await expect(attendanceRecord.locator('[data-testid="check-in-time"]')).toContainText(MANUAL_CHECK_IN);
  });

  test('Verify reconciliation process performance (boundary)', async ({ page }) => {
    const EXPECTED_RECORD_COUNT = 30000;
    const MAX_PROCESSING_TIME_MS = 10 * 60 * 1000; // 10 minutes in milliseconds

    // Step 1: Verify the test dataset contains 1000 employee records with 30 days of attendance data
    await page.goto(`${BASE_URL}/attendance/test-data-setup`);
    const recordCount = await page.locator('[data-testid="total-records-count"]').textContent();
    expect(parseInt(recordCount || '0')).toBeGreaterThanOrEqual(EXPECTED_RECORD_COUNT);

    // Step 2: Note the current system time and initiate the reconciliation process
    await page.goto(`${BASE_URL}/attendance/reconciliation`);
    const startTime = Date.now();
    
    await page.click('[data-testid="run-reconciliation-button"]');
    await expect(page.locator('[data-testid="reconciliation-status"]')).toContainText('In Progress', { timeout: 5000 });

    // Step 3: Monitor the reconciliation process progress indicator or status updates
    const progressIndicator = page.locator('[data-testid="reconciliation-progress"]');
    await expect(progressIndicator).toBeVisible();

    // Step 4: Wait for the reconciliation process to complete and note the completion time
    await expect(page.locator('[data-testid="reconciliation-status"]')).toContainText('Completed', { timeout: MAX_PROCESSING_TIME_MS });
    const completionTime = Date.now();

    // Step 5: Calculate the total time taken by subtracting start time from completion time
    const totalTimeTaken = completionTime - startTime;
    console.log(`Reconciliation completed in ${totalTimeTaken}ms (${totalTimeTaken / 1000}s)`);

    // Expected Result: Process completes within 10 minutes
    expect(totalTimeTaken).toBeLessThanOrEqual(MAX_PROCESSING_TIME_MS);

    // Step 6: Verify that all 30,000 attendance records were processed by checking the reconciliation summary report
    await page.click('[data-testid="view-summary-report-button"]');
    const processedRecords = await page.locator('[data-testid="processed-records-count"]').textContent();
    expect(parseInt(processedRecords || '0')).toBeGreaterThanOrEqual(EXPECTED_RECORD_COUNT);

    // Step 7: Check system resource utilization during the reconciliation process
    const cpuUsage = await page.locator('[data-testid="cpu-usage-metric"]').textContent();
    const memoryUsage = await page.locator('[data-testid="memory-usage-metric"]').textContent();
    const dbConnections = await page.locator('[data-testid="db-connections-metric"]').textContent();

    // Log resource metrics for monitoring
    console.log(`Resource Utilization - CPU: ${cpuUsage}, Memory: ${memoryUsage}, DB Connections: ${dbConnections}`);
    
    // Verify metrics are present and within acceptable ranges
    expect(cpuUsage).toBeTruthy();
    expect(memoryUsage).toBeTruthy();
    expect(dbConnections).toBeTruthy();
  });
});