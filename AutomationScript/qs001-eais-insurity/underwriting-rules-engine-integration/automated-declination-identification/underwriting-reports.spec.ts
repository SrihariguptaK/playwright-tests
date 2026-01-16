import { test, expect } from '@playwright/test';
import { promises as fs } from 'fs';
import * as path from 'path';

test.describe('Underwriting Manager - Report Generation', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Underwriting Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'underwriting.manager@test.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate report generation with filters - Referrals report', async ({ page }) => {
    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="reporting-page"]')).toBeVisible();

    // Select 'Referrals' as the report type from the dropdown menu
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Referrals');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toHaveValue('Referrals');

    // Apply date range filter: Set start date to 30 days ago and end date to today
    const today = new Date();
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(today.getDate() - 30);
    
    const startDate = thirtyDaysAgo.toISOString().split('T')[0];
    const endDate = today.toISOString().split('T')[0];
    
    await page.fill('[data-testid="start-date-input"]', startDate);
    await page.fill('[data-testid="end-date-input"]', endDate);

    // Apply status filter: Select 'Pending' status from the status dropdown
    await page.selectOption('[data-testid="status-filter-dropdown"]', 'Pending');
    await expect(page.locator('[data-testid="status-filter-dropdown"]')).toHaveValue('Pending');

    // Apply user filter: Select a specific underwriter from the user dropdown
    await page.selectOption('[data-testid="user-filter-dropdown"]', { index: 1 });

    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Review the generated report data in the display area
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();

    // Verify report accuracy by cross-checking sample records
    const reportRows = page.locator('[data-testid="report-data-row"]');
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify all rows have 'Pending' status
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      const statusCell = reportRows.nth(i).locator('[data-testid="status-cell"]');
      await expect(statusCell).toContainText('Pending');
    }

    // Change report type to 'Questions' and apply date range filter only
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Questions');
    await page.selectOption('[data-testid="status-filter-dropdown"]', 'All');
    await page.selectOption('[data-testid="user-filter-dropdown"]', 'All');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });

    // Change report type to 'Declinations' and apply status filter only
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Declinations');
    await page.fill('[data-testid="start-date-input"]', '');
    await page.fill('[data-testid="end-date-input"]', '');
    await page.selectOption('[data-testid="status-filter-dropdown"]', 'Completed');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });
  });

  test('Export report to PDF and Excel', async ({ page }) => {
    // Generate a report first
    await page.click('[data-testid="reporting-module-link"]');
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Referrals');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });

    // Get on-screen report data for comparison
    const onScreenRowCount = await page.locator('[data-testid="report-data-row"]').count();
    const firstRowText = await page.locator('[data-testid="report-data-row"]').first().textContent();

    // Locate the 'Export' button or dropdown on the report display page
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();

    // Click 'Export to PDF' option
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);

    // Wait for PDF download to complete and verify
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    const pdfFileName = pdfDownload.suggestedFilename();
    expect(pdfFileName).toContain('.pdf');

    // Verify PDF file exists and has content
    const pdfStats = await fs.stat(pdfPath!);
    expect(pdfStats.size).toBeGreaterThan(0);

    // Return to the report display page and click 'Export to Excel' option
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible();

    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);

    // Wait for Excel download to complete and verify
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    const excelFileName = excelDownload.suggestedFilename();
    expect(excelFileName).toMatch(/\.(xlsx|xls)$/);

    // Verify Excel file exists and has content
    const excelStats = await fs.stat(excelPath!);
    expect(excelStats.size).toBeGreaterThan(0);

    // Verify both files downloaded successfully
    expect(pdfStats.size).toBeGreaterThan(1000); // PDF should have reasonable size
    expect(excelStats.size).toBeGreaterThan(500); // Excel should have reasonable size
  });

  test('Schedule recurring report', async ({ page }) => {
    // Generate a report first
    await page.click('[data-testid="reporting-module-link"]');
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Referrals');
    await page.selectOption('[data-testid="status-filter-dropdown"]', 'Pending');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });

    // Locate and click the 'Schedule Report' button on the report display page
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();

    // Enter a descriptive name for the scheduled report
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Pending Referrals Report');

    // Select recurrence frequency: Choose 'Weekly' from the frequency dropdown
    await page.selectOption('[data-testid="recurrence-frequency-dropdown"]', 'Weekly');
    await expect(page.locator('[data-testid="recurrence-frequency-dropdown"]')).toHaveValue('Weekly');

    // Select day of week: Choose 'Monday' for report generation
    await page.selectOption('[data-testid="day-of-week-dropdown"]', 'Monday');

    // Select time for report generation: Set time to 8:00 AM
    await page.fill('[data-testid="schedule-time-input"]', '08:00');

    // Select report format for delivery: Check both 'PDF' and 'Excel' checkboxes
    await page.check('[data-testid="format-pdf-checkbox"]');
    await page.check('[data-testid="format-excel-checkbox"]');
    await expect(page.locator('[data-testid="format-pdf-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="format-excel-checkbox"]')).toBeChecked();

    // Enter delivery email address: Verify or enter manager's email address
    await page.fill('[data-testid="primary-email-input"]', 'underwriting.manager@test.com');

    // Add additional recipients: Enter two additional email addresses
    await page.fill('[data-testid="additional-recipients-input"]', 'analyst1@test.com, analyst2@test.com');

    // Review the schedule summary displaying all configured settings
    await expect(page.locator('[data-testid="schedule-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('Weekly Pending Referrals Report');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('Monday');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('08:00');

    // Click 'Save Schedule' or 'Confirm' button
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');

    // Navigate to 'Scheduled Reports' section or list
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();

    // Verify the scheduled report entry shows correct details
    const scheduledReport = page.locator('[data-testid="scheduled-report-item"]').filter({ hasText: 'Weekly Pending Referrals Report' });
    await expect(scheduledReport).toBeVisible();
    await expect(scheduledReport.locator('[data-testid="report-name"]')).toContainText('Weekly Pending Referrals Report');
    await expect(scheduledReport.locator('[data-testid="report-frequency"]')).toContainText('Weekly');
    await expect(scheduledReport.locator('[data-testid="report-status"]')).toContainText('Active');
    
    // Verify next run date is displayed
    const nextRunDate = scheduledReport.locator('[data-testid="next-run-date"]');
    await expect(nextRunDate).toBeVisible();
    const nextRunText = await nextRunDate.textContent();
    expect(nextRunText).toBeTruthy();
    expect(nextRunText).toContain('Monday');

    // Verify recipients are displayed
    await expect(scheduledReport.locator('[data-testid="report-recipients"]')).toContainText('underwriting.manager@test.com');
    await expect(scheduledReport.locator('[data-testid="report-recipients"]')).toContainText('analyst1@test.com');
    await expect(scheduledReport.locator('[data-testid="report-recipients"]')).toContainText('analyst2@test.com');

    // Verify formats are displayed
    await expect(scheduledReport.locator('[data-testid="report-formats"]')).toContainText('PDF');
    await expect(scheduledReport.locator('[data-testid="report-formats"]')).toContainText('Excel');
  });

  test('Verify report generation completes within 10 seconds', async ({ page }) => {
    await page.click('[data-testid="reporting-module-link"]');
    await page.selectOption('[data-testid="report-type-dropdown"]', 'Referrals');
    
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-display-area"]')).toBeVisible({ timeout: 10000 });
    const endTime = Date.now();
    
    const generationTime = (endTime - startTime) / 1000;
    expect(generationTime).toBeLessThan(10);
  });

  test('Verify access to reporting module is restricted to authorized managers', async ({ page }) => {
    // Logout current manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as non-manager user (underwriter)
    await page.fill('[data-testid="username-input"]', 'underwriter@test.com');
    await page.fill('[data-testid="password-input"]', 'UnderwriterPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Verify reporting module link is not visible or accessible
    const reportingLink = page.locator('[data-testid="reporting-module-link"]');
    await expect(reportingLink).not.toBeVisible();
    
    // Attempt direct navigation to reporting page
    await page.goto('/reporting');
    
    // Verify access denied or redirect
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
  });
});