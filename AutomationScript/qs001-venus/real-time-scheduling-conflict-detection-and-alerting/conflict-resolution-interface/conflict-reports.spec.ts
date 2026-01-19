import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Conflict Reports - Story 17', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login if needed
    await page.goto(baseURL);
    // Assuming user is already logged in or add login steps here
  });

  test('Validate generation of conflict reports with filters', async ({ page }) => {
    // Action: Access conflict reporting module
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Conflict Reports');
    
    // Expected Result: Reporting UI is displayed
    await expect(page.locator('[data-testid="conflict-reporting-module"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-filters"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    
    // Verify all filter options are available and functional
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="resource-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="severity-filter"]')).toBeVisible();
    
    // Action: Select filters for date range and resource
    // Select date range filter (last 30 days)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('text=Last 30 Days');
    
    // Select a specific resource from dropdown
    await page.click('[data-testid="resource-filter"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Select severity level filter
    await page.click('[data-testid="severity-filter"]');
    await page.click('[data-testid="severity-option-high"]');
    
    // Expected Result: Filters are applied
    await expect(page.locator('[data-testid="date-range-filter"]')).toContainText('Last 30 Days');
    await expect(page.locator('[data-testid="resource-filter"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="severity-filter"]')).toContainText('High');
    
    // Action: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="conflict-report-content"]', { timeout: 10000 });
    
    // Expected Result: Report is displayed with correct data
    await expect(page.locator('[data-testid="conflict-report-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Conflict Report');
    
    // Verify report includes visual elements
    await expect(page.locator('[data-testid="report-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    
    // Review the generated report content for accuracy
    const reportRows = await page.locator('[data-testid="report-row"]').count();
    expect(reportRows).toBeGreaterThan(0);
  });

  test('Verify report export functionality', async ({ page }) => {
    // Generate a conflict report with specific filters applied
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Conflict Reports');
    await expect(page.locator('[data-testid="conflict-reporting-module"]')).toBeVisible();
    
    // Apply filters
    await page.click('[data-testid="date-range-filter"]');
    await page.click('text=Last 30 Days');
    await page.click('[data-testid="resource-filter"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await page.click('[data-testid="severity-filter"]');
    await page.click('[data-testid="severity-option-high"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="conflict-report-content"]', { timeout: 10000 });
    
    // Action: Generate conflict report
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="conflict-report-content"]')).toBeVisible();
    
    // Verify the report content is complete and accurate before export
    const reportTitle = await page.locator('[data-testid="report-title"]').textContent();
    expect(reportTitle).toContain('Conflict Report');
    
    // Action: Export report as PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file is downloaded and formatted correctly
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    
    // Verify PDF file exists and has content
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Return to the report interface
    await expect(page.locator('[data-testid="conflict-report-content"]')).toBeVisible();
    
    // Action: Export report as Excel
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Expected Result: Excel file is downloaded and contains accurate data
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(__dirname, 'downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    
    // Verify Excel file exists and has content
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(0);
    
    // Cleanup downloaded files
    fs.unlinkSync(pdfPath);
    fs.unlinkSync(excelPath);
  });

  test('Test automated report scheduling and delivery', async ({ page }) => {
    // Action: Schedule automated conflict report
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Conflict Reports');
    await expect(page.locator('[data-testid="conflict-reporting-module"]')).toBeVisible();
    
    // Navigate to Schedule Automated Report section
    await page.click('[data-testid="schedule-report-tab"]');
    await expect(page.locator('[data-testid="schedule-report-section"]')).toBeVisible();
    
    // Configure report parameters
    // Select date range filter (previous week)
    await page.click('[data-testid="scheduled-date-range-filter"]');
    await page.click('text=Previous Week');
    
    // Select resource filter
    await page.click('[data-testid="scheduled-resource-filter"]');
    await page.click('[data-testid="scheduled-resource-option-conference-room-a"]');
    
    // Select severity level
    await page.click('[data-testid="scheduled-severity-filter"]');
    await page.click('[data-testid="scheduled-severity-option-high"]');
    
    // Set report frequency to near-term schedule for testing
    await page.click('[data-testid="report-frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-custom"]');
    
    // Set schedule time (5 minutes from now for testing)
    const futureTime = new Date(Date.now() + 5 * 60 * 1000);
    const hours = futureTime.getHours().toString().padStart(2, '0');
    const minutes = futureTime.getMinutes().toString().padStart(2, '0');
    await page.fill('[data-testid="schedule-time-input"]', `${hours}:${minutes}`);
    
    // Select report format as PDF
    await page.click('[data-testid="report-format-dropdown"]');
    await page.click('[data-testid="format-option-pdf"]');
    
    // Enter or confirm email address for delivery
    await page.fill('[data-testid="delivery-email-input"]', 'scheduler@example.com');
    
    // Click Save Schedule button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    
    // Verify the scheduled report appears in the list of active scheduled reports
    await page.click('[data-testid="view-scheduled-reports-link"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduledReportRow = page.locator('[data-testid="scheduled-report-row"]').first();
    await expect(scheduledReportRow).toBeVisible();
    await expect(scheduledReportRow).toContainText('scheduler@example.com');
    await expect(scheduledReportRow).toContainText('PDF');
    
    // Check the scheduled report status
    await expect(scheduledReportRow.locator('[data-testid="schedule-status"]')).toContainText('Active');
    
    // Note: Actual email delivery verification would require email service integration
    // For automation purposes, verify the schedule was created with correct parameters
    await expect(scheduledReportRow.locator('[data-testid="schedule-date-range"]')).toContainText('Previous Week');
    await expect(scheduledReportRow.locator('[data-testid="schedule-resource"]')).toContainText('Conference Room A');
    await expect(scheduledReportRow.locator('[data-testid="schedule-severity"]')).toContainText('High');
  });
});