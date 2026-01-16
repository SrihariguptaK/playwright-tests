import { test, expect } from '@playwright/test';

test.describe('Benchmark Team Performance Against Historical Data', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate benchmarking report comparing current and historical KPIs', async ({ page }) => {
    // Step 1: Navigate to performance reporting module from the main dashboard
    await page.click('[data-testid="performance-reporting-link"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Step 2: Locate and click on 'Benchmarking' option or tab
    await page.click('[data-testid="benchmarking-tab"]');
    await expect(page.locator('[data-testid="benchmarking-interface"]')).toBeVisible();
    
    // Step 3: Select one or more KPIs from the available KPI dropdown list
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity"]');
    await page.click('[data-testid="kpi-option-quality"]');
    await page.click('[data-testid="kpi-option-efficiency"]');
    
    // Step 4: Select current time period
    await page.fill('[data-testid="current-start-date"]', '2024-01-01');
    await page.fill('[data-testid="current-end-date"]', '2024-03-31');
    
    // Step 5: Select historical comparison period
    await page.click('[data-testid="historical-period-dropdown"]');
    await page.click('[data-testid="historical-option-same-period-last-year"]');
    
    // Step 6: Click on 'Generate Benchmarking Report' button
    await page.click('[data-testid="generate-benchmarking-report-button"]');
    
    // Step 7: Wait for benchmarking report generation to complete
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 10000 });
    await expect(page.locator('[data-testid="benchmarking-report-container"]')).toBeVisible();
    
    // Step 8: Review the comparative data section of the report
    await expect(page.locator('[data-testid="comparative-data-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-kpi-data"]')).toBeVisible();
    await expect(page.locator('[data-testid="historical-kpi-data"]')).toBeVisible();
    
    // Step 9: Review the visualizations section of the report
    await expect(page.locator('[data-testid="visualizations-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="performance-gap-chart"]')).toBeVisible();
    
    // Step 10: Verify data completeness and accuracy
    const productivityMetric = await page.locator('[data-testid="kpi-productivity-value"]').textContent();
    expect(productivityMetric).toBeTruthy();
    const qualityMetric = await page.locator('[data-testid="kpi-quality-value"]').textContent();
    expect(qualityMetric).toBeTruthy();
    const efficiencyMetric = await page.locator('[data-testid="kpi-efficiency-value"]').textContent();
    expect(efficiencyMetric).toBeTruthy();
  });

  test('Export benchmarking report', async ({ page }) => {
    // Step 1: Generate benchmarking report
    await page.click('[data-testid="performance-reporting-link"]');
    await page.click('[data-testid="benchmarking-tab"]');
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity"]');
    await page.fill('[data-testid="current-start-date"]', '2024-01-01');
    await page.fill('[data-testid="current-end-date"]', '2024-03-31');
    await page.click('[data-testid="historical-period-dropdown"]');
    await page.click('[data-testid="historical-option-same-period-last-year"]');
    await page.click('[data-testid="generate-benchmarking-report-button"]');
    await expect(page.locator('[data-testid="benchmarking-report-container"]')).toBeVisible();
    
    // Step 2: Locate the export options and click on 'Export to PDF' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Step 3: Wait for PDF generation and download to complete
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
    
    // Step 4: Return to the benchmarking report screen and click on 'Export to Excel' button
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Step 5: Wait for Excel generation and download to complete
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
    
    // Verify both files were downloaded successfully
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Schedule automated benchmarking report delivery', async ({ page }) => {
    // Step 1: Navigate to performance reporting module and access the benchmarking section
    await page.click('[data-testid="performance-reporting-link"]');
    await page.click('[data-testid="benchmarking-tab"]');
    
    // Step 2: Locate and click on 'Schedule Benchmarking Report' button
    await page.click('[data-testid="schedule-benchmarking-report-button"]');
    await expect(page.locator('[data-testid="scheduling-ui"]')).toBeVisible();
    
    // Step 3: Select KPIs to include in the scheduled benchmarking report
    await page.click('[data-testid="scheduled-kpi-dropdown"]');
    await page.click('[data-testid="scheduled-kpi-option-productivity"]');
    await page.click('[data-testid="scheduled-kpi-option-quality"]');
    await page.click('[data-testid="scheduled-kpi-option-efficiency"]');
    await page.click('[data-testid="scheduled-kpi-dropdown"]'); // Close dropdown
    
    // Step 4: Configure comparison settings
    await page.click('[data-testid="comparison-settings-dropdown"]');
    await page.click('[data-testid="comparison-option-same-period-previous-year"]');
    
    // Step 5: Select report frequency
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-monthly"]');
    
    // Step 6: Set the delivery time
    await page.fill('[data-testid="delivery-time-input"]', '09:00');
    
    // Step 7: Enter recipient email addresses
    await page.fill('[data-testid="recipient-email-input"]', 'manager1@example.com');
    await page.click('[data-testid="add-recipient-button"]');
    await page.fill('[data-testid="recipient-email-input"]', 'manager2@example.com');
    await page.click('[data-testid="add-recipient-button"]');
    
    // Step 8: Select report format
    await page.check('[data-testid="format-pdf-checkbox"]');
    await page.check('[data-testid="format-excel-checkbox"]');
    
    // Step 9: Review the schedule summary
    await expect(page.locator('[data-testid="schedule-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="summary-kpis"]')).toContainText('Productivity');
    await expect(page.locator('[data-testid="summary-frequency"]')).toContainText('Monthly');
    await expect(page.locator('[data-testid="summary-recipients"]')).toContainText('manager1@example.com');
    
    // Step 10: Click 'Save Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved');
    
    // Step 11: Navigate to the scheduled reports list to verify
    await page.click('[data-testid="scheduled-reports-list-link"]');
    await expect(page.locator('[data-testid="scheduled-reports-table"]')).toBeVisible();
    
    // Step 12: Verify the new schedule appears in the list
    const scheduleRow = page.locator('[data-testid="schedule-row"]').first();
    await expect(scheduleRow).toBeVisible();
    await expect(scheduleRow.locator('[data-testid="schedule-frequency"]')).toContainText('Monthly');
    await expect(scheduleRow.locator('[data-testid="schedule-recipients"]')).toContainText('manager1@example.com');
    await expect(scheduleRow.locator('[data-testid="schedule-status"]')).toContainText('Active');
    
    // Step 13: Use 'Send Test Report' function if available
    await page.click('[data-testid="send-test-report-button"]');
    await expect(page.locator('[data-testid="test-report-sent-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="test-report-sent-message"]')).toContainText('Test report sent successfully');
  });
});