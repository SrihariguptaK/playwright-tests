import { test, expect } from '@playwright/test';

test.describe('Performance Trends Visualization - Story 8', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Department Manager
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

    // Step 2: Select KPIs from available options
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    await page.click('[data-testid="kpi-option-task-completion-rate"]');
    await page.click('[data-testid="kpi-option-quality-metrics"]');
    
    // Select time period using date pickers
    const endDate = new Date();
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 3);
    
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', endDate.toISOString().split('T')[0]);
    
    // Verify selections are accepted
    await expect(page.locator('[data-testid="selected-kpis"]')).toContainText('productivity score');
    await expect(page.locator('[data-testid="selected-kpis"]')).toContainText('task completion rate');
    await expect(page.locator('[data-testid="selected-time-period"]')).toBeVisible();

    // Step 3: View trend visualization
    await page.click('[data-testid="view-trends-button"]');
    
    // Wait for visualization to render (within 5 seconds as per technical requirements)
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    
    // Verify visualization displays accurate performance trends
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-axis-labels"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-line"]')).toBeVisible();
    await expect(page.locator('[data-testid="data-points"]')).toBeVisible();
    
    // Hover over data points to verify interactivity
    const dataPoint = page.locator('[data-testid="data-point"]').first();
    await dataPoint.hover();
    await expect(page.locator('[data-testid="data-tooltip"]')).toBeVisible();
    
    // Verify trend data is displayed
    const visualizationContainer = page.locator('[data-testid="trend-visualization"]');
    await expect(visualizationContainer).toContainText(/productivity|performance|trend/i);
  });

  test('Export performance report with visualizations', async ({ page }) => {
    // Step 1: Generate performance report with visualizations
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Select KPIs
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    await page.click('[data-testid="kpi-option-task-completion-rate"]');
    
    // Select time period (last 3 months)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 3);
    
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', endDate.toISOString().split('T')[0]);
    
    // Generate visualization
    await page.click('[data-testid="view-trends-button"]');
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    
    // Verify all visualizations are fully loaded
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-line"]')).toBeVisible();
    await expect(page.locator('[data-testid="data-points"]')).toBeVisible();
    
    // Wait for any loading indicators to disappear
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeHidden({ timeout: 5000 });
    
    // Step 2: Click export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-pdf-button"]');
    
    // Verify PDF file is downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/performance.*report.*\.pdf/i);
    
    // Save the download to verify it's a valid file
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Verify download success message or notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText(/exported|downloaded|success/i);
  });

  test('Verify dynamic update of trend visualizations based on user selections', async ({ page }) => {
    // Navigate to Performance Reporting
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Initial selection - 1 month period
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    
    const endDate1 = new Date();
    const startDate1 = new Date();
    startDate1.setMonth(startDate1.getMonth() - 1);
    
    await page.fill('[data-testid="start-date-picker"]', startDate1.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', endDate1.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    const initialDataPoints = await page.locator('[data-testid="data-point"]').count();
    
    // Change selection - 6 months period
    const startDate2 = new Date();
    startDate2.setMonth(startDate2.getMonth() - 6);
    
    await page.fill('[data-testid="start-date-picker"]', startDate2.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify visualization updates dynamically
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible({ timeout: 5000 });
    const updatedDataPoints = await page.locator('[data-testid="data-point"]').count();
    
    // Expect more data points for longer time period
    expect(updatedDataPoints).toBeGreaterThan(initialDataPoints);
  });

  test('Verify system validates time period inputs and handles errors gracefully', async ({ page }) => {
    // Navigate to Performance Reporting
    await page.click('[data-testid="performance-reporting-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    // Select KPI
    await page.click('[data-testid="kpi-selector"]');
    await page.click('[data-testid="kpi-option-productivity-score"]');
    
    // Test invalid date range - end date before start date
    const startDate = new Date();
    const endDate = new Date();
    endDate.setMonth(endDate.getMonth() - 3);
    
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid.*date|end date.*start date/i);
    
    // Verify visualization is not displayed with invalid input
    await expect(page.locator('[data-testid="trend-visualization"]')).not.toBeVisible();
    
    // Test missing KPI selection
    await page.reload();
    await page.click('[data-testid="performance-reporting-menu"]');
    
    const validStartDate = new Date();
    validStartDate.setMonth(validStartDate.getMonth() - 1);
    const validEndDate = new Date();
    
    await page.fill('[data-testid="start-date-picker"]', validStartDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-picker"]', validEndDate.toISOString().split('T')[0]);
    await page.click('[data-testid="view-trends-button"]');
    
    // Verify error for missing KPI selection
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/select.*kpi|kpi.*required/i);
  });
});