import { test, expect } from '@playwright/test';

test.describe('Employee Punctuality Trends Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the attendance dashboard before each test
    await page.goto('/attendance/dashboard');
    // Wait for dashboard to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate punctuality trend chart display and filtering', async ({ page }) => {
    // Verify that punctuality trend charts are visible on the dashboard
    const punctualityChart = page.locator('[data-testid="punctuality-trend-chart"]');
    await expect(punctualityChart).toBeVisible();

    // Locate the employee filter dropdown in the punctuality section
    const employeeFilter = page.locator('[data-testid="employee-filter-dropdown"]');
    await expect(employeeFilter).toBeVisible();

    // Select a specific employee from the employee filter dropdown
    await employeeFilter.click();
    await page.locator('[data-testid="employee-option-john-doe"]').click();

    // Wait for chart to update
    await page.waitForTimeout(1000);

    // Verify the chart data matches the selected employee's attendance records
    const chartTitle = page.locator('[data-testid="chart-title"]');
    await expect(chartTitle).toContainText('John Doe');

    // Verify chart has updated with employee-specific data
    const chartDataPoints = page.locator('[data-testid="chart-data-point"]');
    await expect(chartDataPoints.first()).toBeVisible();

    // Locate the department filter dropdown in the punctuality section
    const departmentFilter = page.locator('[data-testid="department-filter-dropdown"]');
    await expect(departmentFilter).toBeVisible();

    // Select a specific department from the department filter dropdown
    await departmentFilter.click();
    await page.locator('[data-testid="department-option-engineering"]').click();

    // Wait for chart to update
    await page.waitForTimeout(1000);

    // Verify the chart reflects department-level punctuality trends
    const departmentChartTitle = page.locator('[data-testid="chart-title"]');
    await expect(departmentChartTitle).toContainText('Engineering');

    // Locate and review the summary statistics section on the dashboard
    const summaryStatistics = page.locator('[data-testid="summary-statistics-section"]');
    await expect(summaryStatistics).toBeVisible();

    // Verify summary statistics are displayed
    const avgLateArrivals = page.locator('[data-testid="avg-late-arrivals"]');
    await expect(avgLateArrivals).toBeVisible();
    const avgLateArrivalsText = await avgLateArrivals.textContent();
    expect(avgLateArrivalsText).toMatch(/\d+/);

    // Verify that statistics update when filters are changed
    const totalLateCount = page.locator('[data-testid="total-late-count"]');
    const initialLateCount = await totalLateCount.textContent();

    // Change filter and verify statistics update
    await employeeFilter.click();
    await page.locator('[data-testid="employee-option-jane-smith"]').click();
    await page.waitForTimeout(1000);

    const updatedLateCount = await totalLateCount.textContent();
    // Statistics should reflect the filter change
    await expect(totalLateCount).toBeVisible();

    // Click on the 'Export' button in the punctuality trend section
    const exportButton = page.locator('[data-testid="export-trend-button"]');
    await expect(exportButton).toBeVisible();
    await exportButton.click();

    // Select 'PDF' format and initiate the export
    const pdfFormatOption = page.locator('[data-testid="export-format-pdf"]');
    await expect(pdfFormatOption).toBeVisible();

    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    await pdfFormatOption.click();

    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');

    // Return to dashboard and export the trend report in Excel format
    await exportButton.click();
    const excelFormatOption = page.locator('[data-testid="export-format-excel"]');
    await expect(excelFormatOption).toBeVisible();

    // Setup download listener for Excel
    const excelDownloadPromise = page.waitForEvent('download');
    await excelFormatOption.click();

    // Wait for Excel download to complete
    const excelDownload = await excelDownloadPromise;
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
  });

  test('Test real-time update of punctuality data', async ({ page }) => {
    // Navigate to the attendance dashboard and locate the punctuality trend charts
    const punctualityChart = page.locator('[data-testid="punctuality-trend-chart"]');
    await expect(punctualityChart).toBeVisible();

    // Note the current data displayed in the punctuality trend chart
    const initialDataPoints = page.locator('[data-testid="chart-data-point"]');
    const initialCount = await initialDataPoints.count();

    // Get initial timestamp from chart
    const latestTimestamp = page.locator('[data-testid="latest-timestamp"]');
    const initialTimestamp = await latestTimestamp.textContent();

    // Get initial summary statistics
    const totalLateCount = page.locator('[data-testid="total-late-count"]');
    const initialLateCount = await totalLateCount.textContent();

    // Open a separate browser tab to access attendance data entry
    const adminPage = await page.context().newPage();
    await adminPage.goto('/admin/attendance/entry');
    await adminPage.waitForLoadState('networkidle');

    // Create a new attendance entry for an employee with late arrival
    const employeeSelect = adminPage.locator('[data-testid="attendance-employee-select"]');
    await employeeSelect.click();
    await adminPage.locator('[data-testid="employee-option-test-employee"]').click();

    // Set timestamp indicating late arrival (15 minutes after scheduled start time)
    const timestampInput = adminPage.locator('[data-testid="attendance-timestamp-input"]');
    const lateTime = new Date();
    lateTime.setMinutes(lateTime.getMinutes() + 15);
    await timestampInput.fill(lateTime.toISOString().slice(0, 16));

    // Mark as late arrival
    const lateArrivalCheckbox = adminPage.locator('[data-testid="late-arrival-checkbox"]');
    await lateArrivalCheckbox.check();

    // Submit the attendance entry
    const submitButton = adminPage.locator('[data-testid="submit-attendance-button"]');
    await submitButton.click();

    // Wait for confirmation
    await expect(adminPage.locator('[data-testid="success-message"]')).toBeVisible();

    // Return to the dashboard tab with punctuality trend charts
    await page.bringToFront();

    // Wait and observe the punctuality trend chart for automatic updates (monitor for up to 60 seconds)
    await page.waitForTimeout(5000); // Initial wait for real-time update

    // Verify that the new data point appears on the trend chart
    let updatedDataPoints = page.locator('[data-testid="chart-data-point"]');
    let updatedCount = await updatedDataPoints.count();

    // Poll for updates if not immediately visible
    let attempts = 0;
    while (updatedCount === initialCount && attempts < 12) {
      await page.waitForTimeout(5000);
      updatedCount = await updatedDataPoints.count();
      attempts++;
    }

    // Verify new data point is visible
    expect(updatedCount).toBeGreaterThanOrEqual(initialCount);

    // Check if summary statistics have updated to reflect the new attendance entry
    const updatedLateCount = await totalLateCount.textContent();
    const initialLateNumber = parseInt(initialLateCount || '0');
    const updatedLateNumber = parseInt(updatedLateCount || '0');
    expect(updatedLateNumber).toBeGreaterThanOrEqual(initialLateNumber);

    // Simulate another attendance entry with on-time arrival
    await adminPage.bringToFront();
    await adminPage.goto('/admin/attendance/entry');

    await employeeSelect.click();
    await adminPage.locator('[data-testid="employee-option-test-employee-2"]').click();

    // Set timestamp for on-time arrival
    const onTimeTimestamp = new Date();
    await timestampInput.fill(onTimeTimestamp.toISOString().slice(0, 16));

    // Ensure late arrival is not checked
    await lateArrivalCheckbox.uncheck();

    // Submit the on-time attendance entry
    await submitButton.click();
    await expect(adminPage.locator('[data-testid="success-message"]')).toBeVisible();

    // Monitor the dashboard for the second real-time update
    await page.bringToFront();
    await page.waitForTimeout(5000);

    // Verify data consistency across all chart elements and statistics
    const finalDataPoints = await page.locator('[data-testid="chart-data-point"]').count();
    expect(finalDataPoints).toBeGreaterThan(initialCount);

    // Verify chart is still visible and functional
    await expect(punctualityChart).toBeVisible();

    // Verify summary statistics section is updated and consistent
    await expect(summaryStatistics).toBeVisible();
    const onTimeCount = page.locator('[data-testid="on-time-count"]');
    await expect(onTimeCount).toBeVisible();

    // Close admin page
    await adminPage.close();
  });
});