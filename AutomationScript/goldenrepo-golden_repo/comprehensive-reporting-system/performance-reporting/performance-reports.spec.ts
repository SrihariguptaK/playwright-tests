import { test, expect } from '@playwright/test';

test.describe('Performance Reports - Team Lead KPI Evaluation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate performance report with selected KPIs', async ({ page }) => {
    // Step 1: Navigate to performance reporting module from the main dashboard
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Performance Reports');

    // Step 2: Select one or more KPIs from the available KPI dropdown list
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-task-completion"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    await page.click('[data-testid="kpi-option-attendance-rate"]');
    
    // Step 3: Select time period by choosing start date and end date from date picker
    await page.fill('[data-testid="start-date-picker"]', '2024-01-01');
    await page.fill('[data-testid="end-date-picker"]', '2024-01-31');
    await expect(page.locator('[data-testid="start-date-picker"]')).toHaveValue('2024-01-01');
    await expect(page.locator('[data-testid="end-date-picker"]')).toHaveValue('2024-01-31');

    // Step 4: Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Step 5: Wait for report generation to complete
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 10000 });

    // Step 6: Review the generated report for accuracy of KPI metrics
    await expect(page.locator('[data-testid="performance-report-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-task-completion"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-productivity-score"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-attendance-rate"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-analysis-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="benchmark-analysis-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-time-period"]')).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="report-time-period"]')).toContainText('2024-01-31');
  });

  test('Export performance report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate performance report by selecting KPIs and time period, then clicking 'Generate Report'
    await page.click('[data-testid="performance-reports-menu"]');
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-task-completion"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    await page.fill('[data-testid="start-date-picker"]', '2024-01-01');
    await page.fill('[data-testid="end-date-picker"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="performance-report-content"]')).toBeVisible({ timeout: 10000 });

    // Step 2: Locate and click on 'Export to PDF' button in the report toolbar
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Step 3: Wait for PDF download to complete and verify the downloaded PDF file
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('performance-report');
    await downloadPDF.saveAs('./downloads/' + downloadPDF.suggestedFilename());

    // Step 4: Return to the performance report screen and click on 'Export to Excel' button
    await expect(page.locator('[data-testid="performance-report-content"]')).toBeVisible();
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Step 5: Wait for Excel download to complete and verify the downloaded Excel file
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(downloadExcel.suggestedFilename()).toContain('performance-report');
    await downloadExcel.saveAs('./downloads/' + downloadExcel.suggestedFilename());

    // Step 6: Verify data accuracy in both exported files against the on-screen report
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('exported successfully');
  });

  test('Schedule automated performance report delivery', async ({ page }) => {
    // Step 1: Navigate to performance reporting module and locate 'Schedule Report' or 'Automated Delivery' option
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Step 2: Click on 'Schedule Report' or 'Automated Delivery' button
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="scheduling-ui"]')).toBeVisible();
    await expect(page.locator('h2')).toContainText('Schedule Report');

    // Step 3: Select KPIs to include in the scheduled report from the available KPI list
    await page.click('[data-testid="schedule-kpi-dropdown"]');
    await page.click('[data-testid="schedule-kpi-option-task-completion"]');
    await page.click('[data-testid="schedule-kpi-option-productivity-score"]');
    await page.click('[data-testid="schedule-kpi-option-attendance-rate"]');
    await page.click('[data-testid="schedule-kpi-dropdown"]'); // Close dropdown

    // Step 4: Select report frequency (Daily, Weekly, Monthly) from the frequency dropdown
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toContainText('Weekly');

    // Step 5: Set the delivery time using time picker
    await page.fill('[data-testid="delivery-time-picker"]', '09:00');
    await expect(page.locator('[data-testid="delivery-time-picker"]')).toHaveValue('09:00');

    // Step 6: Enter recipient email addresses in the recipients field
    await page.fill('[data-testid="recipients-input"]', 'manager@example.com, director@example.com');
    await expect(page.locator('[data-testid="recipients-input"]')).toHaveValue('manager@example.com, director@example.com');

    // Step 7: Select report format (PDF, Excel, or both) from format options
    await page.check('[data-testid="format-checkbox-pdf"]');
    await page.check('[data-testid="format-checkbox-excel"]');
    await expect(page.locator('[data-testid="format-checkbox-pdf"]')).toBeChecked();
    await expect(page.locator('[data-testid="format-checkbox-excel"]')).toBeChecked();

    // Step 8: Click 'Save Schedule' or 'Activate Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 9: Verify schedule was saved successfully
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    
    // Step 10: Verify the scheduled report appears in the list
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="scheduled-report-item"]').first()).toContainText('Weekly');
    await expect(page.locator('[data-testid="scheduled-report-item"]').first()).toContainText('09:00');
    await expect(page.locator('[data-testid="scheduled-report-item"]').first()).toContainText('manager@example.com');
  });
});