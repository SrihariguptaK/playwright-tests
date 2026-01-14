import { test, expect } from '@playwright/test';

test.describe('Attendance Reports - HR Analyst', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Analyst
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate attendance report with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to attendance reports section from the main dashboard
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="attendance-reports-link"]');
    
    // Expected Result: Report filter form is displayed
    await expect(page.locator('[data-testid="report-filter-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-filter"]')).toBeVisible();
    
    // Step 2: Select a start date and end date for the date range filter
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Step 3: Select one or more employees from the employee filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-1"]');
    await page.click('[data-testid="employee-option-2"]');
    
    // Expected Result: Filters accepted without errors
    await expect(page.locator('[data-testid="filter-error"]')).not.toBeVisible();
    
    // Step 4: Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 15000 });
    
    // Expected Result: Report displays aggregated attendance data matching filters
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-summary-statistics"]')).toBeVisible();
    
    // Step 5: Verify the report contains summary statistics and displays data in a readable format
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows.first()).toBeVisible();
    
    // Verify date range is reflected in report
    const reportHeader = page.locator('[data-testid="report-header"]');
    await expect(reportHeader).toContainText('01/01/2024');
    await expect(reportHeader).toContainText('31/01/2024');
  });

  test('Export attendance report to CSV and Excel (happy-path)', async ({ page }) => {
    // Step 1: Select date range and any desired filters for the attendance report
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="attendance-reports-link"]');
    
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Step 2: Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { timeout: 15000 });
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible();
    
    // Step 3: Locate and click the 'Export to CSV' button
    const csvDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const csvDownload = await csvDownloadPromise;
    
    // Expected Result: CSV file is downloaded with correct data
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    await csvDownload.saveAs(`./downloads/${csvDownload.suggestedFilename()}`);
    
    // Step 4: Return to the report page and click the 'Export to Excel' button
    await page.waitForTimeout(1000); // Brief pause between downloads
    const excelDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const excelDownload = await excelDownloadPromise;
    
    // Expected Result: Excel file is downloaded with correct data
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    await excelDownload.saveAs(`./downloads/${excelDownload.suggestedFilename()}`);
    
    // Verify export success messages
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Schedule automated attendance report (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the attendance reports section and locate the 'Schedule Report' option
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="attendance-reports-link"]');
    
    // Step 2: Click on 'Schedule Report' button
    await page.click('[data-testid="schedule-report-button"]');
    
    // Expected Result: Scheduling form is displayed
    await expect(page.locator('[data-testid="schedule-report-form"]')).toBeVisible();
    
    // Step 3: Enter a report name
    await page.fill('[data-testid="report-name-input"]', 'Monthly Attendance Summary');
    
    // Step 4: Select report frequency as 'Weekly' and choose day of week
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    await page.click('[data-testid="day-of-week-dropdown"]');
    await page.click('[data-testid="day-option-monday"]');
    
    // Step 5: Set the time for report generation
    await page.fill('[data-testid="schedule-time-input"]', '08:00');
    
    // Step 6: Configure report filters
    await page.click('[data-testid="date-range-type-dropdown"]');
    await page.click('[data-testid="date-range-previous-7-days"]');
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-all"]');
    
    // Step 7: Select export format as 'Excel' and enter recipient email addresses
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('[data-testid="format-option-excel"]');
    await page.fill('[data-testid="recipient-emails-input"]', 'manager@company.com, hr.head@company.com');
    
    // Step 8: Click 'Save Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved and confirmation displayed
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    
    // Step 9: Navigate to 'Scheduled Reports' list view
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    // Step 10: Verify the scheduled report appears in the list
    const scheduledReport = page.locator('[data-testid="scheduled-report-item"]').filter({ hasText: 'Monthly Attendance Summary' });
    await expect(scheduledReport).toBeVisible();
    await expect(scheduledReport).toContainText('Weekly');
    await expect(scheduledReport).toContainText('Monday');
    await expect(scheduledReport).toContainText('08:00');
    
    // Step 11: Trigger a test execution of the scheduled report
    await scheduledReport.locator('[data-testid="test-run-button"]').click();
    await expect(page.locator('[data-testid="test-run-initiated-message"]')).toBeVisible();
    
    // Expected Result: Reports are generated and delivered as per schedule
    await page.waitForSelector('[data-testid="test-run-success-message"]', { timeout: 20000 });
    await expect(page.locator('[data-testid="test-run-success-message"]')).toContainText('Report generated and sent successfully');
  });
});