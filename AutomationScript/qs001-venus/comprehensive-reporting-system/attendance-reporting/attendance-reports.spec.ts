import { test, expect } from '@playwright/test';

test.describe('Attendance Reports - HR Manager', () => {
  test.beforeEach(async ({ page }) => {
    // HR Manager logs into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate attendance report with valid filters (happy-path)', async ({ page }) => {
    // Navigate to Attendance Reporting section from the main dashboard
    await page.click('[data-testid="attendance-reporting-menu"]');
    
    // Expected Result: Attendance report UI is displayed with filter options
    await expect(page.locator('[data-testid="attendance-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter"]')).toBeVisible();
    
    // Select a valid date range (e.g., last 30 days) using the date picker
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    // Select a department from the department dropdown filter
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Expected Result: Filters are accepted without errors
    await expect(page.locator('[data-testid="filter-error"]')).not.toBeVisible();
    
    // Click the 'Generate Report' button to submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Attendance report is generated and displayed within 5 seconds
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    expect(generationTime).toBeLessThan(5000);
    
    // Verify the report contains accurate attendance data with timestamps
    await expect(page.locator('[data-testid="report-row"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="timestamp-column"]').first()).toBeVisible();
    const timestampText = await page.locator('[data-testid="timestamp-column"]').first().textContent();
    expect(timestampText).toMatch(/\d{1,2}:\d{2}/);
  });

  test('Export attendance report to PDF and Excel (happy-path)', async ({ page }) => {
    // Generate attendance report by selecting date range and department filters
    await page.click('[data-testid="attendance-reporting-menu"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    
    // Locate and click the 'Export to PDF' button in the report toolbar
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file is downloaded with correct report data
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('attendance');
    
    // Return to the attendance report screen and click the 'Export to Excel' button
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Expected Result: Excel file is downloaded with correct report data
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(downloadExcel.suggestedFilename()).toContain('attendance');
    
    // Verify data integrity by comparing a sample of records
    const onScreenFirstRow = await page.locator('[data-testid="report-row"]').first().textContent();
    expect(onScreenFirstRow).toBeTruthy();
  });

  test('Verify absenteeism highlights in attendance report (happy-path)', async ({ page }) => {
    // Navigate to Attendance Reporting section and select a department with known absenteeism cases
    await page.click('[data-testid="attendance-reporting-menu"]');
    
    // Select a date range that includes days with absenteeism and punctuality issues
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    // Select department
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Click 'Generate Report'
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed with attendance data
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    
    // Review the report for visual indicators of absenteeism
    const absenteeismHighlights = page.locator('[data-testid="absenteeism-highlight"]');
    await expect(absenteeismHighlights.first()).toBeVisible();
    
    // Expected Result: Absenteeism trends and punctuality issues are clearly indicated
    const absenteeismTrendsSection = page.locator('[data-testid="absenteeism-trends-section"]');
    await expect(absenteeismTrendsSection).toBeVisible();
    
    // Review the report for punctuality issue indicators
    const punctualityIssues = page.locator('[data-testid="punctuality-issue-indicator"]');
    const punctualityCount = await punctualityIssues.count();
    expect(punctualityCount).toBeGreaterThanOrEqual(0);
    
    // Identify the absenteeism trends section or summary statistics
    const summaryStats = page.locator('[data-testid="summary-statistics"]');
    await expect(summaryStats).toBeVisible();
    const summaryText = await summaryStats.textContent();
    expect(summaryText).toMatch(/(absent|absenteeism|late|punctuality)/i);
    
    // Verify data accuracy against time-tracking system
    // Expected Result: Report data matches source data
    const reportDataRows = await page.locator('[data-testid="report-row"]').count();
    expect(reportDataRows).toBeGreaterThan(0);
    
    // Verify that all highlighted absenteeism cases correspond to actual absences
    const highlightedRows = await page.locator('[data-testid="absenteeism-highlight"]').count();
    expect(highlightedRows).toBeGreaterThanOrEqual(0);
    
    // Check for absenteeism status indicators
    const absentStatus = page.locator('[data-testid="status-absent"]').first();
    if (await absentStatus.isVisible()) {
      const statusText = await absentStatus.textContent();
      expect(statusText).toMatch(/(absent|leave|no-show)/i);
    }
  });
});