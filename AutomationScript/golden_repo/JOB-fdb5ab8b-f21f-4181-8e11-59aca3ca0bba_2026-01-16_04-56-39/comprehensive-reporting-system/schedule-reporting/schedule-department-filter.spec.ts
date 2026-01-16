import { test, expect } from '@playwright/test';

test.describe('Schedule Reports - Department Filter', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate department filter in schedule reports', async ({ page }) => {
    // Step 1: Navigate to schedule reporting module
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /schedule report/i })).toBeVisible();

    // Step 2: Select a valid date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-month-option"]');
    
    // Step 2: Select department filter
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Sales Department');
    
    // Verify filters accepted without errors
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    await expect(page.locator('.error-notification')).not.toBeVisible();

    // Step 3: Generate schedule report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await expect(page.locator('[data-testid="report-loading"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading"]')).not.toBeVisible({ timeout: 15000 });
    
    // Verify report displays data only for selected department
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    const reportRows = page.locator('[data-testid="report-row"]');
    const rowCount = await reportRows.count();
    
    expect(rowCount).toBeGreaterThan(0);
    
    // Verify each employee record belongs to Sales Department
    for (let i = 0; i < rowCount; i++) {
      const departmentCell = reportRows.nth(i).locator('[data-testid="department-cell"]');
      await expect(departmentCell).toContainText('Sales Department');
    }
    
    // Verify report header shows applied filter
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Sales Department');
  });

  test('Verify export of department filtered schedule reports', async ({ page }) => {
    // Step 1: Navigate to schedule reporting module
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();

    // Select a valid date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-month-option"]');
    
    // Select specific department from filter dropdown
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Engineering Department');

    // Generate schedule report with department filter applied
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await expect(page.locator('[data-testid="report-loading"]')).not.toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    // Capture on-screen report data for comparison
    const onScreenRows = page.locator('[data-testid="report-row"]');
    const onScreenRowCount = await onScreenRows.count();
    const onScreenData: string[] = [];
    
    for (let i = 0; i < Math.min(onScreenRowCount, 5); i++) {
      const employeeName = await onScreenRows.nth(i).locator('[data-testid="employee-name-cell"]').textContent();
      if (employeeName) {
        onScreenData.push(employeeName.trim());
      }
    }

    // Step 2: Export report to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Verify download completed successfully
    expect(download.suggestedFilename()).toMatch(/schedule.*report.*\.pdf/i);
    
    // Save the downloaded file
    const filePath = `./downloads/${download.suggestedFilename()}`;
    await download.saveAs(filePath);
    
    // Verify export success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText(/exported successfully/i);
    
    // Verify the PDF metadata contains department filter information
    const exportMetadata = page.locator('[data-testid="export-metadata"]');
    if (await exportMetadata.isVisible()) {
      await expect(exportMetadata).toContainText('Engineering Department');
    }
  });

  test('Verify filtered report generation performance within 10 seconds', async ({ page }) => {
    // Navigate to schedule reporting module
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();

    // Select date range and department filter
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-month-option"]');
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]');

    // Measure report generation time
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="report-loading"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 10000 });
    
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generated within 10 seconds
    expect(generationTime).toBeLessThanOrEqual(10);
    
    // Verify report contains data
    const reportRows = page.locator('[data-testid="report-row"]');
    expect(await reportRows.count()).toBeGreaterThan(0);
  });

  test('Verify multiple filters can be applied with department filter', async ({ page }) => {
    // Navigate to schedule reporting module
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();

    // Select date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-month-option"]');
    
    // Select department filter
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]');
    
    // Select additional team filter if available
    const teamFilter = page.locator('[data-testid="team-filter-dropdown"]');
    if (await teamFilter.isVisible()) {
      await teamFilter.click();
      await page.click('[data-testid="team-option-first"]');
    }

    // Generate report with multiple filters
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 15000 });
    
    // Verify all filters are applied
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Sales Department');
    
    // Verify report data matches all filters
    const reportRows = page.locator('[data-testid="report-row"]');
    expect(await reportRows.count()).toBeGreaterThan(0);
  });
});