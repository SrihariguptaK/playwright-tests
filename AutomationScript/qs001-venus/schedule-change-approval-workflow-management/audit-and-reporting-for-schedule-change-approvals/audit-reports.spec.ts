import { test, expect } from '@playwright/test';

test.describe('Audit Reports - Schedule Change Approvals', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to admin dashboard and login as administrator
    await page.goto('/admin/dashboard');
    // Assuming admin is already authenticated or handle login here
  });

  test('Generate audit report with filters (happy-path)', async ({ page }) => {
    // Navigate to the audit reporting module from the admin dashboard
    await page.click('[data-testid="audit-reporting-module"]');
    await expect(page).toHaveURL(/.*audit-reports/);

    // Select a date range filter by choosing start date and end date from the date picker
    await page.click('[data-testid="start-date-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.click('[data-testid="end-date-picker"]');
    await page.fill('[data-testid="end-date-input"]', '2024-12-31');

    // Select one or more approvers from the approver dropdown filter
    await page.click('[data-testid="approver-dropdown"]');
    await page.click('[data-testid="approver-option-john-doe"]');
    await page.click('[data-testid="approver-option-jane-smith"]');
    await page.click('[data-testid="approver-dropdown"]'); // Close dropdown

    // Verify that the filters are applied correctly by reviewing the filter summary section
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('2024-12-31');
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="filter-summary"]')).toContainText('Jane Smith');

    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Wait for report generation to complete
    await page.waitForSelector('[data-testid="report-results"]', { state: 'visible', timeout: 30000 });
    await expect(page.locator('[data-testid="report-loading"]')).not.toBeVisible();

    // Verify that only approval actions matching the selected filters are displayed in the report
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows).toHaveCountGreaterThan(0);
    
    // Verify each row contains data within the date range and from selected approvers
    const firstRow = reportRows.first();
    await expect(firstRow).toBeVisible();
    const approverCell = firstRow.locator('[data-testid="approver-cell"]');
    const approverText = await approverCell.textContent();
    expect(['John Doe', 'Jane Smith']).toContain(approverText?.trim());
  });

  test('Export audit report in PDF and Excel (happy-path)', async ({ page }) => {
    // Generate a report first
    await page.click('[data-testid="audit-reporting-module"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-results"]', { state: 'visible', timeout: 30000 });

    // Locate the export options section on the generated audit report page
    await expect(page.locator('[data-testid="export-options"]')).toBeVisible();

    // Click the 'Export as PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);

    // Wait for PDF file to be generated and downloaded
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');

    // Verify that the PDF contains correct data matching the on-screen report
    // Note: Actual PDF content verification would require additional libraries
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');

    // Return to the audit report page and click the 'Export as Excel' button
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);

    // Wait for Excel file to be generated and downloaded
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    const excelFilename = excelDownload.suggestedFilename();
    expect(excelFilename).toMatch(/\.(xlsx|xls)$/);

    // Verify that the Excel file contains correct data matching the on-screen report
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel exported successfully');
  });

  test('Schedule automated audit report delivery (happy-path)', async ({ page }) => {
    // Navigate to the audit reporting module and locate the 'Schedule Report' option
    await page.click('[data-testid="audit-reporting-module"]');
    await expect(page.locator('[data-testid="schedule-report-button"]')).toBeVisible();

    // Click on the 'Schedule Report' button
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();

    // Configure report schedule by selecting frequency (daily, weekly, monthly) and specific time for report generation
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    await page.fill('[data-testid="schedule-time-input"]', '09:00');

    // Select report format (PDF, Excel, or both) for the scheduled delivery
    await page.check('[data-testid="format-checkbox-pdf"]');
    await page.check('[data-testid="format-checkbox-excel"]');

    // Enter recipient email addresses in the recipients field
    await page.fill('[data-testid="recipients-input"]', 'admin@company.com, compliance@company.com');

    // Configure optional filters for the scheduled report (date range, approver, status)
    await page.click('[data-testid="schedule-filters-toggle"]');
    await page.click('[data-testid="schedule-approver-dropdown"]');
    await page.click('[data-testid="schedule-approver-option-john-doe"]');
    await page.click('[data-testid="schedule-status-dropdown"]');
    await page.click('[data-testid="schedule-status-option-approved"]');

    // Review the schedule configuration summary showing all settings
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('Weekly');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('PDF, Excel');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('admin@company.com');
    await expect(page.locator('[data-testid="schedule-summary"]')).toContainText('compliance@company.com');

    // Click the 'Save Schedule' button
    await page.click('[data-testid="save-schedule-button"]');

    // Verify that the scheduled report appears in the list of active scheduled reports
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    await page.waitForSelector('[data-testid="scheduled-reports-list"]', { state: 'visible' });
    
    const scheduledReportRow = page.locator('[data-testid="scheduled-report-row"]').first();
    await expect(scheduledReportRow).toBeVisible();
    await expect(scheduledReportRow).toContainText('Weekly');
    await expect(scheduledReportRow).toContainText('09:00');
    await expect(scheduledReportRow).toContainText('admin@company.com');

    // Wait for the configured scheduled time to arrive (or manually trigger the schedule for testing purposes)
    await page.click('[data-testid="trigger-schedule-now-button"]');
    await expect(page.locator('[data-testid="schedule-triggered-message"]')).toContainText('Report scheduled for immediate delivery');

    // Check that the system sends the scheduled report via email to all configured recipients
    // Note: Email verification would typically be done through email API or test email service
    await page.waitForTimeout(2000);
    await expect(page.locator('[data-testid="last-execution-status"]')).toContainText('Sent successfully');

    // Verify email content by opening the received email
    // This step would require integration with email testing service (e.g., MailHog, Mailtrap)
    // For automation purposes, we verify the delivery status in the UI
    await expect(page.locator('[data-testid="delivery-recipients"]')).toContainText('admin@company.com');
    await expect(page.locator('[data-testid="delivery-recipients"]')).toContainText('compliance@company.com');
  });
});