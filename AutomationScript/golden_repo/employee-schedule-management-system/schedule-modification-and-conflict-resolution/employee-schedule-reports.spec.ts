import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Reports - Story 10', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as Scheduler
    await page.goto(BASE_URL);
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate generation of schedule report with filters', async ({ page }) => {
    // Step 1: Navigate to reporting module
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');
    
    // Expected Result: Report selection UI is displayed
    await expect(page.locator('[data-testid="report-selection-ui"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toBeVisible();

    // Select Employee Schedule Report
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-employee-schedule"]');

    // Step 2: Select date range and employee filter
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Expected Result: Filters applied
    await expect(page.locator('[data-testid="start-date-input"]')).toHaveValue('2024-01-01');
    await expect(page.locator('[data-testid="end-date-input"]')).toHaveValue('2024-01-31');

    // Select employee filter
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-filter-dropdown"]')).toContainText('John Doe');

    // Verify additional filter options are available
    await expect(page.locator('[data-testid="shift-type-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="location-filter"]')).toBeVisible();

    // Step 3: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation to complete
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-indicator"]')).not.toBeVisible({ timeout: 10000 });
    
    // Expected Result: Report is displayed with correct data
    await expect(page.locator('[data-testid="report-display"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-employee-names"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="report-shift-times"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-dates"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-shift-types"]')).toBeVisible();
    
    // Verify summary and detailed views
    await expect(page.locator('[data-testid="report-summary-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-detailed-view"]')).toBeVisible();
  });

  test('Verify export of report in PDF and Excel formats', async ({ page }) => {
    // Navigate to reporting module and generate a schedule report
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-employee-schedule"]');
    
    // Set valid filter criteria
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 1: Generate a schedule report
    await expect(page.locator('[data-testid="report-loading-indicator"]')).not.toBeVisible({ timeout: 10000 });
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="report-display"]')).toBeVisible();
    
    // Locate export options section
    await expect(page.locator('[data-testid="export-options-section"]')).toBeVisible();

    // Step 2: Export report as PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file is downloaded and viewable
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Verify PDF download success
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });

    // Step 3: Export report as Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel file is downloaded and viewable
    const excelFilename = excelDownload.suggestedFilename();
    expect(excelFilename).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    
    // Verify Excel download success
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });
  });

  test('Validate scheduling of automated reports', async ({ page }) => {
    // Navigate to reporting module
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');
    
    // Step 1: Set up automated report generation
    await page.click('[data-testid="schedule-automated-report-button"]');
    
    // Expected Result: Schedule configuration UI is displayed
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();
    
    // Select report type
    await page.click('[data-testid="scheduled-report-type-dropdown"]');
    await page.click('[data-testid="scheduled-report-type-employee-schedule"]');
    
    // Configure report criteria
    await page.click('[data-testid="date-range-preset-dropdown"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    
    await page.click('[data-testid="scheduled-employee-filter-dropdown"]');
    await page.click('[data-testid="scheduled-employee-all"]');
    
    await page.click('[data-testid="scheduled-format-dropdown"]');
    await page.click('[data-testid="scheduled-format-pdf"]');
    
    // Set schedule frequency
    await page.click('[data-testid="schedule-frequency-dropdown"]');
    await page.click('[data-testid="schedule-frequency-daily"]');
    
    // Set schedule time to near-future time (2 minutes from now)
    const futureTime = new Date(Date.now() + 2 * 60 * 1000);
    const hours = futureTime.getHours().toString().padStart(2, '0');
    const minutes = futureTime.getMinutes().toString().padStart(2, '0');
    await page.fill('[data-testid="schedule-time-input"]', `${hours}:${minutes}`);
    
    // Configure delivery method
    await page.fill('[data-testid="delivery-email-input"]', 'scheduler@example.com');
    
    // Save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-report-modal"]')).not.toBeVisible();
    
    // Verify scheduled report appears in list
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduledReportRow = page.locator('[data-testid="scheduled-report-row"]').first();
    await expect(scheduledReportRow).toBeVisible();
    await expect(scheduledReportRow).toContainText('Employee Schedule Report');
    await expect(scheduledReportRow).toContainText('Daily');
    await expect(scheduledReportRow).toContainText('PDF');
    
    // Step 2: Wait for scheduled time
    // Note: In real automation, this would wait for the actual scheduled time
    // For testing purposes, we simulate the wait with a shorter timeout
    await page.waitForTimeout(130000); // Wait 2+ minutes for scheduled execution
    
    // Step 3: Verify report delivery or availability
    await page.reload();
    await page.click('[data-testid="scheduled-reports-tab"]');
    
    // Expected Result: Report is accessible or sent as configured
    const lastRunTimestamp = page.locator('[data-testid="last-run-timestamp"]').first();
    await expect(lastRunTimestamp).toBeVisible();
    await expect(lastRunTimestamp).not.toBeEmpty();
    
    // Verify report status shows successful execution
    const reportStatus = page.locator('[data-testid="scheduled-report-status"]').first();
    await expect(reportStatus).toContainText('Success');
    
    // Check notification or delivery confirmation
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-report-generated"]')).toBeVisible();
  });
});