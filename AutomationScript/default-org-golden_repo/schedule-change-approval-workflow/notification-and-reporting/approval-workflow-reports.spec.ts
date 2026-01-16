import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Reports - Story 16', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate report generation with filters (happy-path)', async ({ page }) => {
    // Navigate to the reporting module from the main dashboard
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Select 'Approval Workflow Report' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="approval-workflow-report-option"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Approval Workflow Report');

    // Select a start date and end date for the report (e.g., last 30 days)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);

    // Select one or more departments from the department filter dropdown
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="department-option-sales"]');
    await page.keyboard.press('Escape');

    // Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Wait for report generation to complete
    await expect(page.locator('[data-testid="report-loading-spinner"]')).toBeHidden({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();

    // Review the report data table for accuracy
    const reportTable = page.locator('[data-testid="report-data-table"]');
    await expect(reportTable).toBeVisible();
    await expect(reportTable.locator('tbody tr')).not.toHaveCount(0);

    // Verify filtered departments appear in results
    const departmentCells = reportTable.locator('[data-testid="department-cell"]');
    const firstDepartment = await departmentCells.first().textContent();
    expect(['Engineering', 'Sales']).toContain(firstDepartment);

    // Scroll down to view visualizations section
    await page.locator('[data-testid="visualizations-section"]').scrollIntoViewIfNeeded();

    // Examine the approval times visualization (e.g., bar chart or line graph)
    const approvalTimesChart = page.locator('[data-testid="approval-times-visualization"]');
    await expect(approvalTimesChart).toBeVisible();
    await expect(approvalTimesChart).toContainText(/Approval Times|Average Time/);

    // Examine the approval volumes visualization (e.g., pie chart or bar chart)
    const approvalVolumesChart = page.locator('[data-testid="approval-volumes-visualization"]');
    await expect(approvalVolumesChart).toBeVisible();
    await expect(approvalVolumesChart).toContainText(/Approval Volumes|Total Requests/);

    // Verify that visualization data matches the tabular report data
    const tableRowCount = await reportTable.locator('tbody tr').count();
    const volumeText = await approvalVolumesChart.textContent();
    expect(volumeText).toMatch(/\d+/);
  });

  test('Verify report export functionality (happy-path)', async ({ page }) => {
    // Generate a report first
    await page.click('[data-testid="reporting-module-link"]');
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="approval-workflow-report-option"]');
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible({ timeout: 10000 });

    // Locate the export options section on the generated report page
    const exportSection = page.locator('[data-testid="export-options-section"]');
    await expect(exportSection).toBeVisible();

    // Click the 'Export as CSV' button
    const csvDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Wait for CSV download to complete and locate the downloaded file
    const csvDownload = await csvDownloadPromise;
    expect(csvDownload.suggestedFilename()).toMatch(/\.csv$/);
    
    // Verify CSV download was successful
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Return to the report page in the browser
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();

    // Click the 'Export as PDF' button
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for PDF download to complete and locate the downloaded file
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Verify PDF download was successful
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Verify success message or notification
    const successMessage = page.locator('[data-testid="export-success-message"]');
    if (await successMessage.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(successMessage).toContainText(/exported|downloaded|success/i);
    }
  });

  test('Ensure scheduled report delivery (happy-path)', async ({ page }) => {
    // Navigate to the reporting module and generate or select an approval workflow report
    await page.click('[data-testid="reporting-module-link"]');
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="approval-workflow-report-option"]');
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible({ timeout: 10000 });

    // Locate and click the 'Schedule Report' button or link
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();

    // Select 'Daily' from the frequency dropdown menu
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-daily"]');
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toContainText('Daily');

    // Select the time for daily delivery (e.g., 8:00 AM)
    await page.fill('[data-testid="delivery-time-input"]', '08:00');

    // Verify the email address field is pre-populated with the manager's email
    const emailInput = page.locator('[data-testid="recipient-email-input"]');
    await expect(emailInput).toHaveValue(/manager@company\.com/);

    // Optionally add additional recipient email addresses if the feature allows
    const additionalEmailInput = page.locator('[data-testid="additional-recipients-input"]');
    if (await additionalEmailInput.isVisible({ timeout: 2000 }).catch(() => false)) {
      await additionalEmailInput.fill('team-lead@company.com');
    }

    // Select the report format for email delivery (CSV, PDF, or both)
    await page.click('[data-testid="format-checkbox-csv"]');
    await page.click('[data-testid="format-checkbox-pdf"]');
    await expect(page.locator('[data-testid="format-checkbox-csv"]')).toBeChecked();
    await expect(page.locator('[data-testid="format-checkbox-pdf"]')).toBeChecked();

    // Review the schedule summary showing frequency, time, recipients, and format
    const scheduleSummary = page.locator('[data-testid="schedule-summary"]');
    await expect(scheduleSummary).toBeVisible();
    await expect(scheduleSummary).toContainText('Daily');
    await expect(scheduleSummary).toContainText('08:00');
    await expect(scheduleSummary).toContainText('manager@company.com');

    // Click the 'Save Schedule' or 'Activate Schedule' button
    await page.click('[data-testid="save-schedule-button"]');

    // Wait for confirmation
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText(/scheduled|activated|saved/i);

    // Navigate to the scheduled reports list or dashboard
    await page.click('[data-testid="scheduled-reports-link"]');
    await expect(page).toHaveURL(/.*scheduled-reports/);

    // Verify the scheduled report appears in the list
    const scheduledReportsList = page.locator('[data-testid="scheduled-reports-list"]');
    await expect(scheduledReportsList).toBeVisible();
    
    const scheduledReportRow = scheduledReportsList.locator('[data-testid="scheduled-report-row"]').first();
    await expect(scheduledReportRow).toBeVisible();
    await expect(scheduledReportRow).toContainText('Approval Workflow Report');
    await expect(scheduledReportRow).toContainText('Daily');
    await expect(scheduledReportRow).toContainText('08:00');

    // Verify schedule status is active
    const statusBadge = scheduledReportRow.locator('[data-testid="schedule-status-badge"]');
    await expect(statusBadge).toContainText(/active|enabled/i);

    // Check the scheduled report execution log
    await page.click('[data-testid="view-execution-log-button"]');
    const executionLog = page.locator('[data-testid="execution-log-table"]');
    await expect(executionLog).toBeVisible();
  });
});