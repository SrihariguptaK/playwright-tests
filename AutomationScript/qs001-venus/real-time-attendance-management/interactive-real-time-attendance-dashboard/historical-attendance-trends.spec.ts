import { test, expect } from '@playwright/test';

test.describe('Historical Attendance Trends - Story 22', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_EMAIL = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager123!';

  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate historical attendance trend display (happy-path)', async ({ page }) => {
    // Navigate to the attendance dashboard
    await page.goto(`${BASE_URL}/dashboard/attendance`);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Locate and click on 'Historical Data' or 'Trends' view option
    await page.click('[data-testid="historical-data-view"]');
    await expect(page.locator('[data-testid="trends-view-container"]')).toBeVisible();

    // Select a time period from the date range selector
    await page.click('[data-testid="time-period-selector"]');
    await page.click('[data-testid="period-option-last-3-months"]');

    // Click 'Apply' or 'View Trends' button to load the historical data
    await page.click('[data-testid="apply-trends-button"]');
    
    // Wait for charts to load
    await page.waitForSelector('[data-testid="trend-chart"]', { state: 'visible' });

    // Verify the trend charts display relevant attendance metrics
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-rate-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-legend"]')).toBeVisible();

    // Locate the department filter dropdown or selector
    await page.click('[data-testid="department-filter-dropdown"]');
    
    // Select a specific department from the filter options
    await page.click('[data-testid="department-option-engineering"]');
    
    // Observe the trend charts update
    await page.waitForTimeout(500); // Wait for chart update animation
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toContainText('Engineering');

    // Locate the location filter dropdown or selector
    await page.click('[data-testid="location-filter-dropdown"]');
    
    // Select a specific location from the filter options
    await page.click('[data-testid="location-option-new-york"]');
    
    // Observe the trend charts update again
    await page.waitForTimeout(500); // Wait for chart update animation
    await expect(page.locator('[data-testid="trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toContainText('New York');

    // Verify chart interactivity by hovering over data points
    await page.hover('[data-testid="chart-data-point-0"]');
    await expect(page.locator('[data-testid="chart-tooltip"]')).toBeVisible();
    
    // Click on chart elements to verify interactivity
    await page.click('[data-testid="chart-data-point-1"]');
    await expect(page.locator('[data-testid="chart-detail-panel"]')).toBeVisible();
  });

  test('Verify export of historical trend reports (happy-path)', async ({ page }) => {
    // Navigate to the historical attendance trends view
    await page.goto(`${BASE_URL}/dashboard/attendance`);
    await page.click('[data-testid="historical-data-view"]');
    await expect(page.locator('[data-testid="trends-view-container"]')).toBeVisible();

    // Select desired time period and apply any filters
    await page.click('[data-testid="time-period-selector"]');
    await page.click('[data-testid="period-option-last-6-months"]');
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]');
    await page.click('[data-testid="location-filter-dropdown"]');
    await page.click('[data-testid="location-option-san-francisco"]');
    await page.click('[data-testid="apply-trends-button"]');
    await page.waitForSelector('[data-testid="trend-chart"]', { state: 'visible' });

    // Locate and click the 'Export' button
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Select 'Export to PDF' option
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Wait for PDF generation to complete
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    
    // Verify PDF download was successful
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Return to the historical trends view and click 'Export' button again
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();

    // Select 'Export to Excel' option
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-option"]');
    
    // Wait for Excel generation to complete
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    
    // Verify Excel download was successful
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
  });

  test('Test chart rendering performance (boundary)', async ({ page }) => {
    // Navigate to the attendance dashboard
    await page.goto(`${BASE_URL}/dashboard/attendance`);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Start performance measurement
    const startTime = Date.now();

    // Click on 'Historical Data' or 'Trends' view to load trend charts
    await page.click('[data-testid="historical-data-view"]');

    // Wait for all trend charts to be fully rendered and interactive
    await page.waitForSelector('[data-testid="trend-chart"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="attendance-rate-chart"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="chart-legend"]', { state: 'visible' });
    
    // Wait for loading indicators to disappear
    await page.waitForSelector('[data-testid="chart-loading-spinner"]', { state: 'hidden', timeout: 6000 });

    // Stop timer when all trend charts are fully rendered
    const endTime = Date.now();
    const renderingTime = (endTime - startTime) / 1000; // Convert to seconds

    // Verify charts render within 5 seconds
    expect(renderingTime).toBeLessThan(5);

    // Verify all chart elements are properly displayed
    await expect(page.locator('[data-testid="chart-x-axis"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-y-axis"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-labels"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-data-points"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-legend"]')).toBeVisible();

    // Test chart interactivity by hovering over data points
    await page.hover('[data-testid="chart-data-point-0"]');
    await expect(page.locator('[data-testid="chart-tooltip"]')).toBeVisible({ timeout: 1000 });

    // Apply a filter and measure the chart re-rendering time
    const reRenderStartTime = Date.now();
    
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-marketing"]');
    
    // Wait for chart to re-render
    await page.waitForSelector('[data-testid="chart-loading-spinner"]', { state: 'hidden', timeout: 6000 });
    
    const reRenderEndTime = Date.now();
    const reRenderingTime = (reRenderEndTime - reRenderStartTime) / 1000;

    // Verify re-rendering also completes within acceptable time
    expect(reRenderingTime).toBeLessThan(5);
    
    // Verify chart is still interactive after re-rendering
    await page.hover('[data-testid="chart-data-point-1"]');
    await expect(page.locator('[data-testid="chart-tooltip"]')).toBeVisible();
  });
});