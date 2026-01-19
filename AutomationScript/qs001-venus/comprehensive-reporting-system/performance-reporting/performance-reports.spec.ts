import { test, expect } from '@playwright/test';

test.describe('Performance Reports - Department Manager', () => {
  test.beforeEach(async ({ page }) => {
    // Department Manager logs into the system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'department.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Generate performance report with selected KPIs', async ({ page }) => {
    // Navigate to Performance Reporting section from the main dashboard
    await page.click('[data-testid="performance-reporting-link"]');
    
    // Performance report UI is displayed with KPI options
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    await expect(page.locator('[data-testid="kpi-options"]')).toBeVisible();
    
    // Select desired KPIs from the available options
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-task-completion-rate"]');
    await page.click('[data-testid="kpi-quality-score"]');
    
    // Apply filters for team selection by choosing a specific team from the dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Apply time period filter by selecting start and end dates
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Selections are accepted without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Click the 'Generate Report' button to submit the report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Performance report is generated and visualized within 5 seconds
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    expect(generationTime).toBeLessThanOrEqual(5);
    
    // Review the generated report for completeness and accuracy
    await expect(page.locator('[data-testid="report-kpi-task-completion"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-quality-score"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-team-name"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-01');
  });

  test('Export performance report to PDF and Excel', async ({ page }) => {
    // Generate performance report by selecting KPIs, team filter, and time period
    await page.click('[data-testid="performance-reporting-link"]');
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-task-completion-rate"]');
    await page.click('[data-testid="kpi-quality-score"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Report is displayed with visualizations
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-toolbar"]')).toBeVisible();
    
    // Locate and click the 'Export to PDF' button in the report toolbar
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // PDF file is downloaded with correct report data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('performance-report');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Return to the performance report page and click the 'Export to Excel' button
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible();
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Excel file is downloaded with correct report data
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(excelDownload.suggestedFilename()).toContain('performance-report');
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
  });

  test('Verify integration of task and attendance data in performance report', async ({ page }) => {
    // Navigate to Performance Reporting section and select KPIs that include both task metrics and attendance metrics
    await page.click('[data-testid="performance-reporting-link"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-tasks-completed"]');
    await page.click('[data-testid="kpi-task-quality-scores"]');
    await page.click('[data-testid="kpi-attendance-rate"]');
    await page.click('[data-testid="kpi-hours-worked"]');
    
    // Select a specific team from the team filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Select a time period for which test data is available and click 'Generate Report'
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Report is displayed with integrated data
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible();
    
    // Review the report to identify task-related data points
    await expect(page.locator('[data-testid="metric-tasks-completed"]')).toBeVisible();
    const tasksCompletedValue = await page.locator('[data-testid="metric-tasks-completed-value"]').textContent();
    expect(tasksCompletedValue).toBeTruthy();
    
    await expect(page.locator('[data-testid="metric-task-quality-scores"]')).toBeVisible();
    const taskQualityValue = await page.locator('[data-testid="metric-task-quality-value"]').textContent();
    expect(taskQualityValue).toBeTruthy();
    
    // Review the report to identify attendance-related data points
    await expect(page.locator('[data-testid="metric-attendance-rate"]')).toBeVisible();
    const attendanceRateValue = await page.locator('[data-testid="metric-attendance-rate-value"]').textContent();
    expect(attendanceRateValue).toBeTruthy();
    
    await expect(page.locator('[data-testid="metric-hours-worked"]')).toBeVisible();
    const hoursWorkedValue = await page.locator('[data-testid="metric-hours-worked-value"]').textContent();
    expect(hoursWorkedValue).toBeTruthy();
    
    // Cross-reference task data in the report against the source task database records
    await page.click('[data-testid="view-data-sources-button"]');
    await expect(page.locator('[data-testid="task-data-source"]')).toBeVisible();
    const taskDataSource = await page.locator('[data-testid="task-data-source-value"]').textContent();
    expect(taskDataSource).toContain('Task Database');
    
    // Cross-reference attendance data in the report against the source attendance database records
    await expect(page.locator('[data-testid="attendance-data-source"]')).toBeVisible();
    const attendanceDataSource = await page.locator('[data-testid="attendance-data-source-value"]').textContent();
    expect(attendanceDataSource).toContain('Attendance Database');
    
    // Review visualized trends (charts and graphs) for task and attendance correlation
    await page.click('[data-testid="close-data-sources-modal"]');
    await expect(page.locator('[data-testid="trend-chart-task-attendance"]')).toBeVisible();
    await expect(page.locator('[data-testid="correlation-visualization"]')).toBeVisible();
    
    // Verify that integrated metrics (combining task and attendance) are calculated correctly
    await expect(page.locator('[data-testid="integrated-metric-productivity"]')).toBeVisible();
    const productivityScore = await page.locator('[data-testid="integrated-metric-productivity-value"]').textContent();
    expect(productivityScore).toBeTruthy();
    expect(parseFloat(productivityScore || '0')).toBeGreaterThan(0);
    
    // Trends accurately reflect performance over time
    await expect(page.locator('[data-testid="trend-line-chart"]')).toBeVisible();
    const trendDataPoints = await page.locator('[data-testid="trend-data-point"]').count();
    expect(trendDataPoints).toBeGreaterThan(0);
  });
});