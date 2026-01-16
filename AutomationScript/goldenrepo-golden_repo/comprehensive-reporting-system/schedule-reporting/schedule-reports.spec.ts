import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Schedule Reports - Operations Manager', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as Operations Manager
    await page.goto(BASE_URL);
    await page.fill('[data-testid="username-input"]', 'operations.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 10000 });
  });

  test('Generate schedule report with valid filters', async ({ page }) => {
    // Step 1: Navigate to schedule reporting module from the main dashboard
    await page.click('[data-testid="schedule-reports-menu"]');
    
    // Expected Result: Schedule report UI is displayed with filter options
    await expect(page.locator('[data-testid="schedule-report-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();

    // Step 2: Select a valid start date from the date range picker
    await page.click('[data-testid="start-date-input"]');
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 7);
    const startDateStr = startDate.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-input"]', startDateStr);
    
    // Step 3: Select a valid end date that is after the start date
    await page.click('[data-testid="end-date-input"]');
    const endDate = new Date();
    const endDateStr = endDate.toISOString().split('T')[0];
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    
    // Expected Result: Filters accepted without errors
    await expect(page.locator('[data-testid="date-validation-error"]')).not.toBeVisible();
    
    // Step 4: Select one or more teams from the team filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="team-option-operations"]');
    await page.click('[data-testid="team-filter-dropdown"]'); // Close dropdown
    
    // Verify selected teams are displayed
    await expect(page.locator('[data-testid="selected-team-engineering"]')).toBeVisible();
    await expect(page.locator('[data-testid="selected-team-operations"]')).toBeVisible();
    
    // Step 5: Click the 'Generate Report' button to submit the report generation request
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 6: Wait for report generation to complete
    await expect(page.locator('[data-testid="report-loading-spinner"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 10000 });
    
    // Step 7: Review the generated report content for accuracy
    // Expected Result: Report is generated displaying schedules and conflicts accurately
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Schedule Report');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText(startDateStr);
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText(endDateStr);
    await expect(page.locator('[data-testid="report-team-filter"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="report-team-filter"]')).toContainText('Operations');
    
    // Verify schedule data is displayed
    await expect(page.locator('[data-testid="schedule-table"]')).toBeVisible();
    const scheduleRows = page.locator('[data-testid="schedule-row"]');
    await expect(scheduleRows).not.toHaveCount(0);
    
    // Verify conflicts are highlighted if present
    const conflictIndicators = page.locator('[data-testid="conflict-indicator"]');
    const conflictCount = await conflictIndicators.count();
    if (conflictCount > 0) {
      await expect(conflictIndicators.first()).toBeVisible();
      await expect(conflictIndicators.first()).toHaveClass(/conflict|warning|alert/);
    }
  });

  test('Export schedule report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate schedule report with valid date range and team filters
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-page"]')).toBeVisible();
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 7);
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    
    const endDate = new Date();
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 10000 });
    
    // Expected Result: Report displayed on screen
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();
    
    // Step 2: Locate and click the 'Export to PDF' button in the report toolbar
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Step 3: Wait for PDF export to complete
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file downloads with correct report content
    expect(downloadPDF.suggestedFilename()).toMatch(/schedule.*report.*\.pdf/i);
    const pdfPath = path.join(__dirname, 'downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Step 4: Return to the schedule report page in the application
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();
    
    // Step 5: Locate and click the 'Export to Excel' button in the report toolbar
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Step 6: Wait for Excel export to complete
    const downloadExcel = await downloadPromiseExcel;
    
    // Expected Result: Excel file downloads with correct report data
    expect(downloadExcel.suggestedFilename()).toMatch(/schedule.*report.*\.(xlsx|xls)/i);
    const excelPath = path.join(__dirname, 'downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(0);
    
    // Cleanup downloaded files
    fs.unlinkSync(pdfPath);
    fs.unlinkSync(excelPath);
  });

  test('Schedule automated report generation and email delivery', async ({ page }) => {
    // Step 1: Navigate to the schedule reporting module and click on 'Schedule Automated Reports' option
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-page"]')).toBeVisible();
    await page.click('[data-testid="schedule-automated-reports-button"]');
    
    // Expected Result: Scheduling UI is displayed
    await expect(page.locator('[data-testid="automated-schedule-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-frequency-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="recipient-email-input"]')).toBeVisible();
    
    // Step 2: Select report frequency (daily, weekly, or monthly) from the dropdown
    await page.click('[data-testid="report-frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    await expect(page.locator('[data-testid="report-frequency-dropdown"]')).toContainText('Weekly');
    
    // Step 3: Set the specific time for report generation
    await page.fill('[data-testid="report-time-input"]', '09:00');
    
    // Step 4: Configure date range parameters for the automated report
    await page.click('[data-testid="date-range-parameter-dropdown"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    await expect(page.locator('[data-testid="date-range-parameter-dropdown"]')).toContainText('Last 7 days');
    
    // Step 5: Select team filters to be applied to the automated report
    await page.click('[data-testid="automated-team-filter-dropdown"]');
    await page.click('[data-testid="automated-team-option-engineering"]');
    await page.click('[data-testid="automated-team-option-operations"]');
    await page.click('[data-testid="automated-team-filter-dropdown"]'); // Close dropdown
    
    // Step 6: Enter valid recipient email addresses
    await page.fill('[data-testid="recipient-email-input"]', 'manager1@company.com, manager2@company.com');
    
    // Expected Result: Parameters accepted and saved
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();
    
    // Step 7: Select export format for the automated report
    await page.click('[data-testid="export-format-pdf-checkbox"]');
    await page.click('[data-testid="export-format-excel-checkbox"]');
    await expect(page.locator('[data-testid="export-format-pdf-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="export-format-excel-checkbox"]')).toBeChecked();
    
    // Step 8: Click 'Save Schedule' button to save the automated report configuration
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for save confirmation
    await expect(page.locator('[data-testid="schedule-save-success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-save-success-message"]')).toContainText('Schedule saved successfully');
    
    // Close modal
    await page.click('[data-testid="close-modal-button"]');
    await expect(page.locator('[data-testid="automated-schedule-modal"]')).not.toBeVisible();
    
    // Step 9: Verify scheduled report appears in the list
    await page.click('[data-testid="view-scheduled-reports-button"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduledReport = page.locator('[data-testid="scheduled-report-item"]').first();
    await expect(scheduledReport).toBeVisible();
    await expect(scheduledReport).toContainText('Weekly');
    await expect(scheduledReport).toContainText('09:00');
    await expect(scheduledReport).toContainText('manager1@company.com');
    
    // Step 10: Trigger a test execution of the scheduled report
    await page.click('[data-testid="test-run-scheduled-report-button"]');
    await expect(page.locator('[data-testid="test-run-confirmation-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="test-run-confirmation-message"]')).toContainText('Test report sent successfully');
    
    // Expected Result: Email received with correct report attachment
    // Note: Actual email verification would require integration with email testing service
    // This validates the system confirms the email was sent
    await expect(page.locator('[data-testid="last-execution-status"]')).toContainText('Success');
    await expect(page.locator('[data-testid="last-execution-time"]')).toBeVisible();
  });
});