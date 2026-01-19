import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Absenteeism Trend Highlighting in Attendance Reports', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as HR Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'HRManager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify absenteeism trend highlighting in attendance report (happy-path)', async ({ page }) => {
    // Navigate to Attendance Reporting section from the main dashboard
    await page.click('[data-testid="attendance-reporting-menu"]');
    await expect(page.locator('[data-testid="attendance-reporting-section"]')).toBeVisible();
    
    // Select a time period filter of at least 30 days to enable trend analysis
    await page.click('[data-testid="time-period-filter"]');
    await page.click('[data-testid="time-period-last-30-days"]');
    await expect(page.locator('[data-testid="time-period-filter"]')).toContainText('Last 30 Days');
    
    // Select a department from the department dropdown filter
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-filter"]')).toContainText('Engineering');
    
    // Enable the absenteeism trend analysis option if available as a separate toggle
    const trendToggle = page.locator('[data-testid="absenteeism-trend-toggle"]');
    if (await trendToggle.isVisible()) {
      await trendToggle.click();
      await expect(trendToggle).toBeChecked();
    }
    
    // Click 'Generate Report' button to request report generation with trend analysis
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated and displayed
    await expect(page.locator('[data-testid="attendance-report"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-loading-indicator"]')).not.toBeVisible();
    
    // Review the report for visual absenteeism trend indicators
    const trendChart = page.locator('[data-testid="absenteeism-trend-chart"]');
    await expect(trendChart).toBeVisible();
    
    const trendGraph = page.locator('[data-testid="absenteeism-trend-graph"]');
    const trendHeatmap = page.locator('[data-testid="absenteeism-heatmap"]');
    const hasTrendVisualization = (await trendChart.isVisible()) || (await trendGraph.isVisible()) || (await trendHeatmap.isVisible());
    expect(hasTrendVisualization).toBeTruthy();
    
    // Examine specific trend highlights including increasing/decreasing patterns
    const trendIndicators = page.locator('[data-testid="trend-indicator"]');
    await expect(trendIndicators.first()).toBeVisible();
    const trendCount = await trendIndicators.count();
    expect(trendCount).toBeGreaterThan(0);
    
    // Verify peak absence days are highlighted
    const peakAbsenceDays = page.locator('[data-testid="peak-absence-day"]');
    if (await peakAbsenceDays.count() > 0) {
      await expect(peakAbsenceDays.first()).toBeVisible();
    }
    
    // Verify recurring patterns are shown
    const recurringPatterns = page.locator('[data-testid="recurring-pattern-indicator"]');
    if (await recurringPatterns.count() > 0) {
      await expect(recurringPatterns.first()).toBeVisible();
    }
    
    // Verify that individual employees with concerning absenteeism trends are highlighted or flagged
    const flaggedEmployees = page.locator('[data-testid="flagged-employee"]');
    if (await flaggedEmployees.count() > 0) {
      await expect(flaggedEmployees.first()).toBeVisible();
      const flaggedEmployeeName = await flaggedEmployees.first().textContent();
      expect(flaggedEmployeeName).toBeTruthy();
    }
    
    // Check the accuracy of trend detection by comparing identified trends with actual attendance data
    const trendAccuracyIndicator = page.locator('[data-testid="trend-accuracy-score"]');
    if (await trendAccuracyIndicator.isVisible()) {
      const accuracyText = await trendAccuracyIndicator.textContent();
      expect(accuracyText).toBeTruthy();
    }
    
    // Verify absenteeism trends are clearly indicated visually
    const absenteeismHighlights = page.locator('[data-testid="absenteeism-highlight"]');
    await expect(absenteeismHighlights.first()).toBeVisible();
    
    // Click 'Export to PDF' button to export the report with trend highlights
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Verify PDF download was successful
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', downloadPDF.suggestedFilename());
    await downloadPDF.saveAs(pdfPath);
    
    // Verify the PDF file exists and has content
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Return to report screen and click 'Export to Excel' button
    await expect(page.locator('[data-testid="attendance-report"]')).toBeVisible();
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Verify Excel download was successful
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(__dirname, 'downloads', downloadExcel.suggestedFilename());
    await downloadExcel.saveAs(excelPath);
    
    // Verify the Excel file exists and has content
    expect(fs.existsSync(excelPath)).toBeTruthy();
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(0);
    
    // Verify exported report includes absenteeism highlights
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('exported successfully');
    
    // Cleanup downloaded files
    if (fs.existsSync(pdfPath)) {
      fs.unlinkSync(pdfPath);
    }
    if (fs.existsSync(excelPath)) {
      fs.unlinkSync(excelPath);
    }
  });
  
  test('Verify absenteeism trend highlighting with different time periods', async ({ page }) => {
    // Navigate to Attendance Reporting section
    await page.click('[data-testid="attendance-reporting-menu"]');
    await expect(page.locator('[data-testid="attendance-reporting-section"]')).toBeVisible();
    
    // Select 60 days time period
    await page.click('[data-testid="time-period-filter"]');
    await page.click('[data-testid="time-period-last-60-days"]');
    
    // Select department
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-sales"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report"]')).toBeVisible({ timeout: 10000 });
    
    // Verify report is displayed with absenteeism trends
    await expect(page.locator('[data-testid="absenteeism-trend-chart"]')).toBeVisible();
    const trendIndicators = page.locator('[data-testid="trend-indicator"]');
    await expect(trendIndicators.first()).toBeVisible();
  });
  
  test('Verify absenteeism trend filtering by department', async ({ page }) => {
    // Navigate to Attendance Reporting section
    await page.click('[data-testid="attendance-reporting-menu"]');
    await expect(page.locator('[data-testid="attendance-reporting-section"]')).toBeVisible();
    
    // Select time period
    await page.click('[data-testid="time-period-filter"]');
    await page.click('[data-testid="time-period-last-30-days"]');
    
    // Select Marketing department
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-marketing"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report"]')).toBeVisible({ timeout: 10000 });
    
    // Verify department filter is applied
    await expect(page.locator('[data-testid="report-department-label"]')).toContainText('Marketing');
    
    // Verify absenteeism highlights are shown for selected department
    await expect(page.locator('[data-testid="absenteeism-highlight"]')).toBeVisible();
  });
});