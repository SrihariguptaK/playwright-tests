import { test, expect } from '@playwright/test';

test.describe('Audit Reports - System Administrator', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Log in as System Administrator
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate generation of audit reports with filters', async ({ page }) => {
    // Action: Navigate to Audit Reports page
    await page.click('[data-testid="audit-reports-menu"]');
    
    // Expected Result: Audit reports page is accessible
    await expect(page).toHaveURL(/.*audit-reports/);
    await expect(page.locator('[data-testid="audit-reports-header"]')).toBeVisible();
    
    // Action: Select date range filter
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    const endDate = new Date();
    
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', endDate.toISOString().split('T')[0]);
    
    // Action: Select user filter
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-john-doe"]');
    
    // Action: Select approval status filter
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    
    // Expected Result: Filters are applied
    await expect(page.locator('[data-testid="selected-user-filter"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="selected-status-filter"]')).toContainText('Approved');
    
    // Action: Generate report and measure time
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is generated and displayed within 10 seconds
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible({ timeout: 10000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    expect(generationTime).toBeLessThan(10);
    
    // Verify report content matches filters
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible();
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows.first()).toBeVisible();
  });

  test('Verify export of audit reports in CSV and PDF', async ({ page }) => {
    // Navigate to Audit Reports page
    await page.click('[data-testid="audit-reports-menu"]');
    await expect(page).toHaveURL(/.*audit-reports/);
    
    // Apply filters
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', new Date().toISOString().split('T')[0]);
    
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    
    // Action: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible();
    
    // Note the number of records for verification
    const recordCountText = await page.locator('[data-testid="report-record-count"]').textContent();
    const recordCount = parseInt(recordCountText?.match(/\d+/)?.[0] || '0');
    expect(recordCount).toBeGreaterThan(0);
    
    // Action: Export report as CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);
    
    // Expected Result: CSV file downloads with correct data
    expect(csvDownload.suggestedFilename()).toMatch(/.*\.csv$/);
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();
    
    // Action: Export report as PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file downloads with correct formatting
    expect(pdfDownload.suggestedFilename()).toMatch(/.*\.pdf$/);
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
  });

  test('Ensure scheduling of recurring audit reports', async ({ page }) => {
    // Navigate to Audit Reports page
    await page.click('[data-testid="audit-reports-menu"]');
    await expect(page).toHaveURL(/.*audit-reports/);
    
    // Action: Click Schedule Report button
    await page.click('[data-testid="schedule-report-button"]');
    
    // Expected Result: Schedule form is displayed
    await expect(page.locator('[data-testid="schedule-report-form"]')).toBeVisible();
    
    // Action: Enter descriptive name for scheduled report
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Approval Audit');
    
    // Action: Configure report filters
    await page.click('[data-testid="schedule-date-range-dropdown"]');
    await page.click('[data-testid="date-range-option-last-7-days"]');
    
    await page.click('[data-testid="schedule-user-dropdown"]');
    await page.click('[data-testid="user-option-all-users"]');
    
    await page.click('[data-testid="schedule-status-dropdown"]');
    await page.click('[data-testid="status-option-all-statuses"]');
    
    // Action: Select recurrence frequency
    await page.click('[data-testid="recurrence-frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    
    // Action: Select day of week and time
    await page.click('[data-testid="day-of-week-dropdown"]');
    await page.click('[data-testid="day-option-monday"]');
    
    await page.fill('[data-testid="schedule-time-input"]', '09:00');
    
    // Action: Select report formats
    await page.check('[data-testid="format-checkbox-csv"]');
    await page.check('[data-testid="format-checkbox-pdf"]');
    
    // Expected Result: Format checkboxes are selected
    await expect(page.locator('[data-testid="format-checkbox-csv"]')).toBeChecked();
    await expect(page.locator('[data-testid="format-checkbox-pdf"]')).toBeChecked();
    
    // Action: Enter delivery email address
    await page.fill('[data-testid="delivery-email-input"]', 'admin@system.com');
    
    // Action: Save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved successfully
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    
    // Action: Navigate to Scheduled Reports list
    await page.click('[data-testid="scheduled-reports-tab"]');
    
    // Expected Result: Scheduled report appears in the list
    await expect(page.locator('[data-testid="scheduled-reports-table"]')).toBeVisible();
    
    const scheduledReportRow = page.locator('[data-testid="scheduled-report-row"]', {
      hasText: 'Weekly Approval Audit'
    });
    await expect(scheduledReportRow).toBeVisible();
    
    // Verify schedule details
    await expect(scheduledReportRow).toContainText('Weekly');
    await expect(scheduledReportRow).toContainText('Monday');
    await expect(scheduledReportRow).toContainText('09:00');
    
    // Verify next scheduled run date is displayed
    const nextRunDate = scheduledReportRow.locator('[data-testid="next-run-date"]');
    await expect(nextRunDate).toBeVisible();
    const nextRunText = await nextRunDate.textContent();
    expect(nextRunText).toBeTruthy();
  });
});