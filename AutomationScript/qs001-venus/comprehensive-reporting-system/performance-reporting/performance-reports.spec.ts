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
    await page.click('[data-testid="kpi-task-completion-rate"]');
    await page.click('[data-testid="kpi-attendance-percentage"]');
    await page.click('[data-testid="kpi-quality-metrics"]');
    
    // Apply filters for team by selecting a specific team from the dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Apply time period filter by selecting start and end dates
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Selections are accepted without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Click the 'Generate Report' button to submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Performance report is generated and visualized within 5 seconds
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    expect(generationTime).toBeLessThanOrEqual(5);
    
    // Verify report contains selected KPIs
    await expect(page.locator('[data-testid="report-kpi-task-completion"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-attendance"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-kpi-quality"]')).toBeVisible();
  });

  test('Export performance report to PDF and Excel', async ({ page }) => {
    // Generate performance report by selecting KPIs, team filter, and time period
    await page.click('[data-testid="performance-reporting-link"]');
    await page.click('[data-testid="kpi-task-completion-rate"]');
    await page.click('[data-testid="kpi-attendance-percentage"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Report is displayed with visualizations
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-charts"]')).toBeVisible();
    
    // Locate and click the 'Export to PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // PDF file is downloaded with correct report data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('performance-report');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Return to the performance report screen and click the 'Export to Excel' button
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
    // Navigate to Performance Reporting section and select a specific team
    await page.click('[data-testid="performance-reporting-link"]');
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Select KPIs that include both task-related and attendance-related metrics
    await page.click('[data-testid="kpi-task-completion-rate"]');
    await page.click('[data-testid="kpi-attendance-percentage"]');
    
    // Select a time period and click 'Generate Report'
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Report is displayed with integrated data
    await expect(page.locator('[data-testid="performance-report-visualization"]')).toBeVisible();
    
    // Access task data and verify integration
    const taskCompletionRate = await page.locator('[data-testid="report-task-completion-value"]').textContent();
    expect(taskCompletionRate).toBeTruthy();
    expect(parseFloat(taskCompletionRate || '0')).toBeGreaterThanOrEqual(0);
    expect(parseFloat(taskCompletionRate || '0')).toBeLessThanOrEqual(100);
    
    // Access attendance data and verify integration
    const attendancePercentage = await page.locator('[data-testid="report-attendance-value"]').textContent();
    expect(attendancePercentage).toBeTruthy();
    expect(parseFloat(attendancePercentage || '0')).toBeGreaterThanOrEqual(0);
    expect(parseFloat(attendancePercentage || '0')).toBeLessThanOrEqual(100);
    
    // Verify data accuracy against task and attendance sources
    await expect(page.locator('[data-testid="report-task-data-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-attendance-data-section"]')).toBeVisible();
    
    // Review visualized trends for correctness
    await expect(page.locator('[data-testid="trend-line-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-bar-graph"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-indicators"]')).toBeVisible();
    
    // Verify trends accurately reflect performance over time
    const trendDataPoints = await page.locator('[data-testid="trend-data-point"]').count();
    expect(trendDataPoints).toBeGreaterThan(0);
    
    // Verify report data matches source data
    const reportDataAccuracy = await page.locator('[data-testid="data-accuracy-indicator"]').getAttribute('data-accuracy');
    expect(parseFloat(reportDataAccuracy || '0')).toBeGreaterThanOrEqual(95);
  });
});