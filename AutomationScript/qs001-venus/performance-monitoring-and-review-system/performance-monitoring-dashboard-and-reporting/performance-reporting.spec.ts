import { test, expect } from '@playwright/test';

test.describe('Performance Reporting - Story 20', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Performance Analyst
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'performance.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate report generation with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to Reporting page
    await page.click('[data-testid="nav-reporting"]');
    await expect(page).toHaveURL(/.*reporting/);
    await expect(page.locator('[data-testid="reporting-page-header"]')).toBeVisible();

    // Step 2: Select desired performance metrics from the metrics dropdown
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-goal-completion-rate"]');
    await page.click('[data-testid="metric-performance-score"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Goal Completion Rate');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Performance Score');

    // Step 3: Select one or more review cycles from the review cycle dropdown
    await page.click('[data-testid="review-cycle-dropdown"]');
    await page.click('[data-testid="review-cycle-q1-2024"]');
    await page.click('[data-testid="review-cycle-q2-2024"]');
    await expect(page.locator('[data-testid="selected-review-cycles"]')).toContainText('Q1 2024');
    await expect(page.locator('[data-testid="selected-review-cycles"]')).toContainText('Q2 2024');

    // Step 4: Apply filters by selecting date range
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-03-31');
    await expect(page.locator('[data-testid="date-range-start"]')).toHaveValue('2024-01-01');
    await expect(page.locator('[data-testid="date-range-end"]')).toHaveValue('2024-03-31');

    // Step 5: Apply additional filters by selecting department
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-engineering"]');
    await page.click('[data-testid="department-sales"]');
    await expect(page.locator('[data-testid="selected-departments"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="selected-departments"]')).toContainText('Sales');

    // Step 6: Apply role filter by selecting specific roles
    await page.click('[data-testid="role-filter-dropdown"]');
    await page.click('[data-testid="role-manager"]');
    await page.click('[data-testid="role-individual-contributor"]');
    await expect(page.locator('[data-testid="selected-roles"]')).toContainText('Manager');
    await expect(page.locator('[data-testid="selected-roles"]')).toContainText('Individual Contributor');

    // Step 7: Click the 'Generate Report' button
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 8: Review the generated report display
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    // Verify report generation time is under 5 seconds
    expect(generationTime).toBeLessThan(5000);
    
    // Verify charts and tables are displayed with filtered data
    await expect(page.locator('[data-testid="report-trend-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-summary-table"]')).toBeVisible();
    
    // Step 9: Verify the accuracy of displayed data
    await expect(page.locator('[data-testid="report-summary-table"]')).toContainText('Goal Completion Rate');
    await expect(page.locator('[data-testid="report-summary-table"]')).toContainText('Performance Score');
    await expect(page.locator('[data-testid="report-filters-applied"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="report-filters-applied"]')).toContainText('Sales');
    await expect(page.locator('[data-testid="report-filters-applied"]')).toContainText('Q1 2024');
    await expect(page.locator('[data-testid="report-filters-applied"]')).toContainText('Q2 2024');
  });

  test('Validate report export functionality (happy-path)', async ({ page }) => {
    // Step 1: Verify that a report is currently displayed on the Reporting page
    await page.click('[data-testid="nav-reporting"]');
    await expect(page).toHaveURL(/.*reporting/);
    
    // Generate a basic report first
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-performance-score"]');
    await page.click('[data-testid="review-cycle-dropdown"]');
    await page.click('[data-testid="review-cycle-q1-2024"]');
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Capture report data for verification
    const reportTitle = await page.locator('[data-testid="report-title"]').textContent();
    const reportMetrics = await page.locator('[data-testid="report-summary-table"]').textContent();
    
    // Step 2: Locate and click the 'Export' button or dropdown menu
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    // Step 3: Select 'Export to PDF' option from the export menu
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    // Step 4: Verify PDF file is downloaded
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Step 5: Return to the Reporting page and click the 'Export' button again
    await page.waitForTimeout(1000); // Wait for download to complete
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    // Step 6: Select 'Export to Excel' option from the export menu
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-option"]')
    ]);
    
    // Step 7: Verify Excel file is downloaded
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    
    // Step 8: Verify export success messages
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('exported successfully');
    
    // Verify both files were downloaded with correct naming convention
    expect(pdfDownload.suggestedFilename()).toContain('performance-report');
    expect(excelDownload.suggestedFilename()).toContain('performance-report');
  });
});