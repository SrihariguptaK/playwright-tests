import { test, expect } from '@playwright/test';

test.describe('Attendance Trend Graphs - Manager Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate attendance trend graph display (happy-path)', async ({ page }) => {
    // Navigate to the attendance dashboard from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="attendance-dashboard-link"]');
    await expect(page).toHaveURL(/.*attendance-dashboard/);

    // Locate the date range selector in the trend visualization section
    const trendSection = page.locator('[data-testid="trend-visualization-section"]');
    await expect(trendSection).toBeVisible();

    // Select a start date from the date picker (e.g., first day of current month)
    const startDatePicker = page.locator('[data-testid="start-date-picker"]');
    await startDatePicker.click();
    const currentDate = new Date();
    const firstDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const startDateFormatted = firstDayOfMonth.toISOString().split('T')[0];
    await startDatePicker.fill(startDateFormatted);

    // Select an end date from the date picker (e.g., last day of current month)
    const endDatePicker = page.locator('[data-testid="end-date-picker"]');
    await endDatePicker.click();
    const lastDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    const endDateFormatted = lastDayOfMonth.toISOString().split('T')[0];
    await endDatePicker.fill(endDateFormatted);

    // Click the 'Apply' or 'Update' button to apply the selected date range
    await page.click('[data-testid="apply-date-range-button"]');

    // Wait for graphs to update
    await page.waitForResponse(response => 
      response.url().includes('/api/dashboard/attendance/trends') && response.status() === 200
    );

    // Verify that trend graphs update to show attendance data for selected range
    const trendGraphs = page.locator('[data-testid="attendance-trend-graphs"]');
    await expect(trendGraphs).toBeVisible();

    // Verify that absenteeism rates trend graph is displayed on the dashboard
    const absenteeismGraph = page.locator('[data-testid="absenteeism-rates-graph"]');
    await expect(absenteeismGraph).toBeVisible();

    // Verify that late arrival trends graph is displayed on the dashboard
    const lateArrivalGraph = page.locator('[data-testid="late-arrival-trends-graph"]');
    await expect(lateArrivalGraph).toBeVisible();

    // Verify graphs accurately reflect attendance metrics
    const graphDataPoints = page.locator('[data-testid="graph-data-point"]');
    await expect(graphDataPoints.first()).toBeVisible();
    const dataPointCount = await graphDataPoints.count();
    expect(dataPointCount).toBeGreaterThan(0);

    // Cross-verify the displayed attendance metrics with source data records
    const absenteeismRate = await page.locator('[data-testid="absenteeism-rate-value"]').textContent();
    expect(absenteeismRate).toMatch(/\d+(\.\d+)?%/);

    const lateArrivalRate = await page.locator('[data-testid="late-arrival-rate-value"]').textContent();
    expect(lateArrivalRate).toMatch(/\d+(\.\d+)?%/);
  });

  test('Validate graph export functionality (happy-path)', async ({ page }) => {
    // Navigate to attendance dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="attendance-dashboard-link"]');
    await expect(page.locator('[data-testid="trend-visualization-section"]')).toBeVisible();

    // Locate the export button on the trend graph section
    const exportButton = page.locator('[data-testid="export-graph-button"]');
    await expect(exportButton).toBeVisible();

    // Click the export button to open export options
    await exportButton.click();
    const exportMenu = page.locator('[data-testid="export-options-menu"]');
    await expect(exportMenu).toBeVisible();

    // Select 'Export as Image' option from the menu
    const downloadPromiseImage = page.waitForEvent('download');
    await page.click('[data-testid="export-as-image-option"]');
    const downloadImage = await downloadPromiseImage;

    // Verify image file is downloaded
    expect(downloadImage.suggestedFilename()).toMatch(/\.(png|jpg|jpeg)$/i);
    const imageFilePath = await downloadImage.path();
    expect(imageFilePath).toBeTruthy();

    // Return to the dashboard and click the export button again
    await page.waitForTimeout(500);
    await exportButton.click();
    await expect(exportMenu).toBeVisible();

    // Select 'Export as PDF' option from the menu
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-as-pdf-option"]');
    const downloadPDF = await downloadPromisePDF;

    // Verify PDF file is downloaded
    expect(downloadPDF.suggestedFilename()).toMatch(/\.pdf$/i);
    const pdfFilePath = await downloadPDF.path();
    expect(pdfFilePath).toBeTruthy();
  });

  test('Test graph rendering performance (happy-path)', async ({ page }) => {
    // Navigate to the attendance dashboard from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="attendance-dashboard-link"]');

    // Start timer when the trend visualization section begins to load
    const startTime = Date.now();

    // Wait for trend visualization section to be visible
    const trendSection = page.locator('[data-testid="trend-visualization-section"]');
    await expect(trendSection).toBeVisible();

    // Wait for all trend graphs to be fully rendered
    await page.waitForLoadState('networkidle');
    const absenteeismGraph = page.locator('[data-testid="absenteeism-rates-graph"]');
    const lateArrivalGraph = page.locator('[data-testid="late-arrival-trends-graph"]');
    
    await expect(absenteeismGraph).toBeVisible();
    await expect(lateArrivalGraph).toBeVisible();

    // Wait for graph elements to be interactive
    await page.waitForSelector('[data-testid="graph-data-point"]', { state: 'visible' });

    // Stop timer when all trend graphs are fully rendered and interactive
    const endTime = Date.now();
    const renderingTime = (endTime - startTime) / 1000;

    // Verify that graphs render within 3 seconds
    expect(renderingTime).toBeLessThanOrEqual(3);

    // Verify that graphs are interactive (hover over data points)
    const firstDataPoint = page.locator('[data-testid="graph-data-point"]').first();
    await firstDataPoint.hover();
    
    // Verify tooltip appears on hover
    const tooltip = page.locator('[data-testid="graph-tooltip"]');
    await expect(tooltip).toBeVisible({ timeout: 2000 });

    // Repeat the test by selecting a different date range and measure rendering time again
    const startDatePicker = page.locator('[data-testid="start-date-picker"]');
    const endDatePicker = page.locator('[data-testid="end-date-picker"]');
    
    const previousMonth = new Date();
    previousMonth.setMonth(previousMonth.getMonth() - 1);
    const firstDayPrevMonth = new Date(previousMonth.getFullYear(), previousMonth.getMonth(), 1);
    const lastDayPrevMonth = new Date(previousMonth.getFullYear(), previousMonth.getMonth() + 1, 0);

    await startDatePicker.fill(firstDayPrevMonth.toISOString().split('T')[0]);
    await endDatePicker.fill(lastDayPrevMonth.toISOString().split('T')[0]);

    // Start second measurement
    const startTime2 = Date.now();
    await page.click('[data-testid="apply-date-range-button"]');

    // Wait for graphs to re-render
    await page.waitForResponse(response => 
      response.url().includes('/api/dashboard/attendance/trends') && response.status() === 200
    );
    await expect(absenteeismGraph).toBeVisible();
    await expect(lateArrivalGraph).toBeVisible();
    await page.waitForSelector('[data-testid="graph-data-point"]', { state: 'visible' });

    const endTime2 = Date.now();
    const renderingTime2 = (endTime2 - startTime2) / 1000;

    // Verify second rendering also meets performance requirement
    expect(renderingTime2).toBeLessThanOrEqual(3);
  });
});