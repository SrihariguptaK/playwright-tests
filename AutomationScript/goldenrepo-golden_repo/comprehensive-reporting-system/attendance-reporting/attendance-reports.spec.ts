import { test, expect } from '@playwright/test';

test.describe('Attendance Reports - HR Specialist', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Specialist
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'hr.specialist@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate attendance report with valid parameters', async ({ page }) => {
    // Action: Navigate to attendance reporting module
    await page.click('[data-testid="attendance-reports-menu"]');
    
    // Expected Result: Attendance report UI is displayed
    await expect(page.locator('[data-testid="attendance-report-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Attendance Reports');
    
    // Action: Select valid date range and team
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Expected Result: Filters accepted
    await expect(page.locator('[data-testid="start-date-input"]')).toHaveValue('2024-01-01');
    await expect(page.locator('[data-testid="end-date-input"]')).toHaveValue('2024-01-31');
    await expect(page.locator('[data-testid="team-dropdown"]')).toContainText('Engineering');
    
    // Action: Generate report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Attendance report with summaries and anomalies is displayed
    await expect(page.locator('[data-testid="attendance-report-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="daily-summary-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="monthly-summary-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="anomalies-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
  });

  test('Export attendance report to CSV and PDF', async ({ page }) => {
    // Action: Generate attendance report
    await page.click('[data-testid="attendance-reports-menu"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="attendance-report-results"]')).toBeVisible();
    
    // Action: Export report to CSV
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const downloadCSV = await downloadPromiseCSV;
    
    // Expected Result: CSV file downloaded with correct data
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    expect(downloadCSV.suggestedFilename()).toContain('attendance');
    
    // Action: Export report to PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file downloaded with correct formatting
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('attendance');
  });

  test('Schedule automated attendance report delivery', async ({ page }) => {
    // Action: Access scheduling options
    await page.click('[data-testid="attendance-reports-menu"]');
    await page.click('[data-testid="schedule-report-button"]');
    
    // Expected Result: Scheduling UI displayed
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();
    
    // Action: Set schedule and recipient
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Attendance Summary');
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    await page.fill('[data-testid="schedule-time-input"]', '08:00');
    await page.fill('[data-testid="start-date-schedule-input"]', '2024-02-01');
    await page.fill('[data-testid="recipient-email-input"]', 'hr@company.com, manager@company.com');
    await page.click('[data-testid="report-format-dropdown"]');
    await page.click('[data-testid="format-option-pdf"]');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Action: Verify report email received at scheduled time
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-item"]').first()).toContainText('Weekly Attendance Summary');
    await expect(page.locator('[data-testid="schedule-item"]').first()).toContainText('08:00');
    await expect(page.locator('[data-testid="schedule-item"]').first()).toContainText('hr@company.com');
  });

  test('Create and save attendance report schedule (happy-path)', async ({ page }) => {
    // Navigate to the attendance reports section from the main dashboard
    await page.click('[data-testid="attendance-reports-menu"]');
    await expect(page.locator('[data-testid="attendance-report-page"]')).toBeVisible();
    
    // Click on 'Schedule Report' or 'Create Schedule' button
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();
    
    // Enter a descriptive name for the scheduled report
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Attendance Summary');
    
    // Select report frequency from dropdown (Daily, Weekly, or Monthly)
    await page.click('[data-testid="frequency-dropdown"]');
    await expect(page.locator('[data-testid="frequency-option-daily"]')).toBeVisible();
    await expect(page.locator('[data-testid="frequency-option-weekly"]')).toBeVisible();
    await expect(page.locator('[data-testid="frequency-option-monthly"]')).toBeVisible();
    await page.click('[data-testid="frequency-option-weekly"]');
    
    // Set the time for report generation
    await page.fill('[data-testid="schedule-time-input"]', '08:00');
    
    // Select the start date for the schedule
    await page.fill('[data-testid="start-date-schedule-input"]', '2024-02-01');
    
    // Enter recipient email addresses in the recipients field
    await page.fill('[data-testid="recipient-email-input"]', 'hr@company.com, manager@company.com');
    
    // Select report format (PDF, Excel, CSV) from available options
    await page.click('[data-testid="report-format-dropdown"]');
    await expect(page.locator('[data-testid="format-option-pdf"]')).toBeVisible();
    await expect(page.locator('[data-testid="format-option-excel"]')).toBeVisible();
    await expect(page.locator('[data-testid="format-option-csv"]')).toBeVisible();
    await page.click('[data-testid="format-option-pdf"]');
    
    // Review all entered schedule parameters on the form
    await expect(page.locator('[data-testid="schedule-name-input"]')).toHaveValue('Weekly Attendance Summary');
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="schedule-time-input"]')).toHaveValue('08:00');
    await expect(page.locator('[data-testid="start-date-schedule-input"]')).toHaveValue('2024-02-01');
    await expect(page.locator('[data-testid="recipient-email-input"]')).toHaveValue('hr@company.com, manager@company.com');
    await expect(page.locator('[data-testid="report-format-dropdown"]')).toContainText('PDF');
    
    // Click 'Save Schedule' or 'Create Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify the schedule details in the scheduled reports list
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    const scheduleItem = page.locator('[data-testid="schedule-item"]').filter({ hasText: 'Weekly Attendance Summary' });
    await expect(scheduleItem).toBeVisible();
    await expect(scheduleItem).toContainText('Weekly');
    await expect(scheduleItem).toContainText('08:00');
    await expect(scheduleItem).toContainText('hr@company.com');
    await expect(scheduleItem).toContainText('PDF');
  });

  test('Verify automated report delivery (happy-path)', async ({ page }) => {
    // Note the scheduled execution time from the scheduled reports list
    await page.click('[data-testid="attendance-reports-menu"]');
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduleItem = page.locator('[data-testid="schedule-item"]').first();
    await expect(scheduleItem).toBeVisible();
    const scheduledTime = await scheduleItem.locator('[data-testid="schedule-time"]').textContent();
    
    // Navigate to the execution logs or report history section
    await page.click('[data-testid="execution-logs-tab"]');
    await expect(page.locator('[data-testid="execution-logs-list"]')).toBeVisible();
    
    // Verify latest execution entry exists
    const latestExecution = page.locator('[data-testid="execution-log-item"]').first();
    await expect(latestExecution).toBeVisible();
    await expect(latestExecution).toContainText('Completed');
    await expect(latestExecution.locator('[data-testid="execution-status"]')).toContainText('Success');
    
    // Verify execution details
    await latestExecution.click();
    await expect(page.locator('[data-testid="execution-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="execution-report-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="execution-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="execution-recipients"]')).toContainText('hr@company.com');
    await expect(page.locator('[data-testid="execution-format"]')).toBeVisible();
    
    // Verify report content metadata
    await expect(page.locator('[data-testid="report-record-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-date-range"]')).toBeVisible();
    
    // Download and verify the generated report from execution history
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-report-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('attendance');
    
    // Verify delivery confirmation
    await expect(page.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="delivery-recipients-count"]')).toBeVisible();
  });
});