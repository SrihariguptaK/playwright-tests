import { test, expect } from '@playwright/test';

test.describe('Performance Trends Visualization - Story 8', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Department Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'department.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View performance trend visualization for selected time period', async ({ page }) => {
    // Step 1: Navigate to Performance Reporting section
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /Performance Report/i })).toBeVisible();

    // Step 2: Select KPIs and time period
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-rate"]');
    await page.click('[data-testid="kpi-option-quality-score"]');
    await page.click('[data-testid="kpi-option-task-completion-rate"]');
    
    // Select time period
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 3);
    const endDate = new Date();
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    await expect(page.locator('[data-testid="kpi-selector"]')).toContainText('productivity rate');
    await expect(page.locator('[data-testid="start-date-input"]')).toHaveValue(startDate.toISOString().split('T')[0]);
    await expect(page.locator('[data-testid="end-date-input"]')).toHaveValue(endDate.toISOString().split('T')[0]);

    // Step 3: View trend visualization
    await page.click('[data-testid="view-trends-button"]');
    
    // Wait for visualization to render (within 5 seconds as per technical requirements)
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    
    // Verify visualization displays accurate performance trends
    await expect(page.locator('[data-testid="chart-data-points"]')).toHaveCount(await page.locator('[data-testid="chart-data-points"]').count());
    
    // Hover over data points to view detailed values
    const firstDataPoint = page.locator('[data-testid="chart-data-point"]').first();
    await firstDataPoint.hover();
    await expect(page.locator('[data-testid="tooltip"]')).toBeVisible();
    await expect(page.locator('[data-testid="tooltip-value"]')).toBeVisible();
    
    // Verify trend direction is displayed
    const trendIndicator = page.locator('[data-testid="trend-indicator"]');
    await expect(trendIndicator).toBeVisible();
    const trendText = await trendIndicator.textContent();
    expect(['increasing', 'decreasing', 'stable'].some(trend => trendText?.toLowerCase().includes(trend))).toBeTruthy();
    
    // Change time period to different date range
    const newStartDate = new Date();
    newStartDate.setMonth(newStartDate.getMonth() - 6);
    await page.fill('[data-testid="start-date-input"]', newStartDate.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify visualization updates dynamically
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="chart-data-points"]')).toHaveCount(await page.locator('[data-testid="chart-data-points"]').count());
  });

  test('Export performance report with visualizations', async ({ page }) => {
    // Step 1: Generate performance report with visualizations
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Select KPIs
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-rate"]');
    await page.click('[data-testid="kpi-option-quality-score"]');
    
    // Select time period
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 2);
    const endDate = new Date();
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    // Generate visualization
    await page.click('[data-testid="view-trends-button"]');
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    
    // Verify all desired visualizations are visible before export
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-data-points"]').first()).toBeVisible();
    
    // Capture on-screen data values for verification
    const onScreenDataPoints = await page.locator('[data-testid="chart-data-point"]').count();
    expect(onScreenDataPoints).toBeGreaterThan(0);
    
    // Step 2: Click export to PDF
    const reportToolbar = page.locator('[data-testid="report-toolbar"]');
    await expect(reportToolbar).toBeVisible();
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/performance.*report.*\.pdf$/i);
    
    // Verify PDF file is downloaded
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
    
    // Verify download completed successfully
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText(/exported successfully|download complete/i);
    
    // Save the file for verification
    const downloadPath = `./downloads/performance-report-${Date.now()}.pdf`;
    await download.saveAs(downloadPath);
  });

  test('Validate time period inputs and handle errors gracefully', async ({ page }) => {
    // Navigate to Performance Reporting section
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Test invalid time period (end date before start date)
    const startDate = new Date();
    const endDate = new Date();
    endDate.setMonth(endDate.getMonth() - 3);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/end date.*before.*start date|invalid.*date range/i);
    
    // Test empty KPI selection
    await page.fill('[data-testid="start-date-input"]', endDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', startDate.toISOString().split('T')[0]);
    
    // Clear any selected KPIs if present
    const clearKpiButton = page.locator('[data-testid="clear-kpi-selection"]');
    if (await clearKpiButton.isVisible()) {
      await clearKpiButton.click();
    }
    
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify error handling for missing KPI selection
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/select.*kpi|kpi.*required/i);
  });

  test('Dynamic update of trend visualizations based on user selections', async ({ page }) => {
    // Navigate to Performance Reporting section
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Initial selection
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-rate"]');
    
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 1);
    const endDate = new Date();
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="view-trends-button"]');
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    
    const initialDataPointCount = await page.locator('[data-testid="chart-data-point"]').count();
    
    // Change KPI selection
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-quality-score"]');
    
    // Verify visualization updates dynamically
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    
    // Change time period
    const newStartDate = new Date();
    newStartDate.setMonth(newStartDate.getMonth() - 2);
    await page.fill('[data-testid="start-date-input"]', newStartDate.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify dynamic update
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    const updatedDataPointCount = await page.locator('[data-testid="chart-data-point"]').count();
    
    // Verify data points changed due to different time period
    expect(updatedDataPointCount).toBeGreaterThan(0);
  });
});