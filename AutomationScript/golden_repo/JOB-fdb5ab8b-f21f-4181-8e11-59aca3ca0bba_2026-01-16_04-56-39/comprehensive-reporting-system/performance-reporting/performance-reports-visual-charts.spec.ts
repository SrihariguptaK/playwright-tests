import { test, expect } from '@playwright/test';

test.describe('Performance Reports with Visual Charts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate visual chart rendering in performance reports', async ({ page }) => {
    // Navigate to the performance reporting module from the dashboard
    await page.click('[data-testid="performance-reporting-link"]');
    await expect(page).toHaveURL(/.*performance-reporting/);

    // Select desired KPIs from the KPI dropdown menu
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity-rate"]');
    await page.click('[data-testid="kpi-option-task-completion-rate"]');

    // Select chart types for each KPI
    await page.selectOption('[data-testid="chart-type-productivity-rate"]', 'bar');
    await page.selectOption('[data-testid="chart-type-task-completion-rate"]', 'line');

    // Select team and time period filters for the report
    await page.selectOption('[data-testid="team-filter"]', 'engineering-team');
    await page.selectOption('[data-testid="time-period-filter"]', 'last-30-days');

    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Wait for report generation and chart rendering to complete (should be within 10 seconds)
    await page.waitForSelector('[data-testid="performance-report-container"]', { timeout: 10000 });
    await page.waitForSelector('[data-testid="chart-productivity-rate"]', { state: 'visible', timeout: 10000 });
    await page.waitForSelector('[data-testid="chart-task-completion-rate"]', { state: 'visible', timeout: 10000 });

    // Verify that each chart accurately represents the corresponding KPI data
    const productivityChart = await page.locator('[data-testid="chart-productivity-rate"]');
    await expect(productivityChart).toBeVisible();
    await expect(productivityChart).toHaveAttribute('data-chart-type', 'bar');

    const taskCompletionChart = await page.locator('[data-testid="chart-task-completion-rate"]');
    await expect(taskCompletionChart).toBeVisible();
    await expect(taskCompletionChart).toHaveAttribute('data-chart-type', 'line');

    // Verify chart data is present
    const chartDataPoints = await page.locator('[data-testid="chart-productivity-rate"] [data-chart-element="data-point"]').count();
    expect(chartDataPoints).toBeGreaterThan(0);

    // Change chart types for one or more KPIs using the customization options
    await page.selectOption('[data-testid="chart-type-productivity-rate"]', 'line');

    // Click 'Regenerate Report' or 'Update Charts' button
    await page.click('[data-testid="regenerate-report-button"]');

    // Wait for charts to update with new chart types
    await page.waitForSelector('[data-testid="chart-productivity-rate"]', { state: 'visible', timeout: 10000 });

    // Verify data consistency between original and updated charts
    const updatedProductivityChart = await page.locator('[data-testid="chart-productivity-rate"]');
    await expect(updatedProductivityChart).toBeVisible();
    await expect(updatedProductivityChart).toHaveAttribute('data-chart-type', 'line');

    // Verify chart still contains data after update
    const updatedChartDataPoints = await page.locator('[data-testid="chart-productivity-rate"] [data-chart-element="data-point"]').count();
    expect(updatedChartDataPoints).toBeGreaterThan(0);
    expect(updatedChartDataPoints).toBe(chartDataPoints);
  });

  test('Verify export of performance reports with embedded charts', async ({ page }) => {
    // Navigate to performance reporting module and select KPIs and chart types
    await page.click('[data-testid="performance-reporting-link"]');
    await expect(page).toHaveURL(/.*performance-reporting/);

    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity-rate"]');
    await page.click('[data-testid="kpi-option-task-completion-rate"]');

    await page.selectOption('[data-testid="chart-type-productivity-rate"]', 'bar');
    await page.selectOption('[data-testid="chart-type-task-completion-rate"]', 'line');

    await page.selectOption('[data-testid="team-filter"]', 'engineering-team');
    await page.selectOption('[data-testid="time-period-filter"]', 'last-30-days');

    // Click 'Generate Report' button to generate performance report with charts
    await page.click('[data-testid="generate-report-button"]');

    // Verify that all charts are fully rendered and visible on screen
    await page.waitForSelector('[data-testid="performance-report-container"]', { timeout: 10000 });
    await page.waitForSelector('[data-testid="chart-productivity-rate"]', { state: 'visible', timeout: 10000 });
    await page.waitForSelector('[data-testid="chart-task-completion-rate"]', { state: 'visible', timeout: 10000 });

    const productivityChart = await page.locator('[data-testid="chart-productivity-rate"]');
    await expect(productivityChart).toBeVisible();

    const taskCompletionChart = await page.locator('[data-testid="chart-task-completion-rate"]');
    await expect(taskCompletionChart).toBeVisible();

    // Note the chart types, data points, and visual elements displayed in the on-screen report
    const productivityChartType = await productivityChart.getAttribute('data-chart-type');
    const taskCompletionChartType = await taskCompletionChart.getAttribute('data-chart-type');
    const productivityDataPoints = await page.locator('[data-testid="chart-productivity-rate"] [data-chart-element="data-point"]').count();
    const taskCompletionDataPoints = await page.locator('[data-testid="chart-task-completion-rate"] [data-chart-element="data-point"]').count();

    expect(productivityChartType).toBe('bar');
    expect(taskCompletionChartType).toBe('line');
    expect(productivityDataPoints).toBeGreaterThan(0);
    expect(taskCompletionDataPoints).toBeGreaterThan(0);

    // Click on 'Export to PDF' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');

    // Wait for PDF download to complete
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');

    // Verify PDF was downloaded successfully
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Return to the performance report screen and click on 'Export to Excel' button
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');

    // Wait for Excel download to complete
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);

    // Verify Excel was downloaded successfully
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();

    // Verify export success messages
    const pdfExportSuccess = await page.locator('[data-testid="export-success-message"]').first();
    await expect(pdfExportSuccess).toContainText(/exported successfully|download complete/i);
  });
});