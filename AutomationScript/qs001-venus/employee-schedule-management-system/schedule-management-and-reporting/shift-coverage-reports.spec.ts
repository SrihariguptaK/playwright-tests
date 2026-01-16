import { test, expect } from '@playwright/test';

test.describe('Shift Coverage Reports - Manager Reporting', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'managerpass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate shift coverage report for a date range (happy-path)', async ({ page }) => {
    // Step 1: Navigate to reporting section
    await page.click('[data-testid="reports-menu"]');
    await expect(page.locator('[data-testid="report-options"]')).toBeVisible();
    await expect(page.locator('text=Shift Coverage Report')).toBeVisible();

    // Step 2: Select shift coverage report and specify date range
    await page.selectOption('[data-testid="report-type-dropdown"]', 'shift-coverage');
    await page.fill('[data-testid="from-date-input"]', '2024-01-01');
    await page.fill('[data-testid="to-date-input"]', '2024-01-31');
    await page.selectOption('[data-testid="department-filter-dropdown"]', 'Sales');
    
    // Verify parameters are accepted
    await expect(page.locator('[data-testid="from-date-input"]')).toHaveValue('2024-01-01');
    await expect(page.locator('[data-testid="to-date-input"]')).toHaveValue('2024-01-31');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toHaveValue('Sales');

    // Step 3: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation (should complete within 5 seconds per requirements)
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 5000 });
    
    // Verify report is displayed with accurate data
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Shift Coverage Report');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('01/01/2024 - 01/31/2024');
    await expect(page.locator('[data-testid="report-department"]')).toContainText('Sales');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    
    // Verify data accuracy by checking for expected columns
    await expect(page.locator('[data-testid="report-table-header"]')).toContainText('Employee Name');
    await expect(page.locator('[data-testid="report-table-header"]')).toContainText('Total Hours');
    await expect(page.locator('[data-testid="report-table-header"]')).toContainText('Shift Coverage');
    
    // Verify at least one row of data is present
    const rowCount = await page.locator('[data-testid="report-data-row"]').count();
    expect(rowCount).toBeGreaterThan(0);
  });

  test('Export report to PDF and Excel (happy-path)', async ({ page }) => {
    // Step 1: Generate a shift coverage report first
    await page.click('[data-testid="reports-menu"]');
    await page.selectOption('[data-testid="report-type-dropdown"]', 'shift-coverage');
    await page.fill('[data-testid="from-date-input"]', '2024-01-01');
    await page.fill('[data-testid="to-date-input"]', '2024-01-31');
    await page.selectOption('[data-testid="department-filter-dropdown"]', 'Sales');
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report is displayed
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();

    // Step 2: Export to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF download
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('shift-coverage');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Step 3: Export to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel download
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(excelDownload.suggestedFilename()).toContain('shift-coverage');
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    
    // Verify both files were downloaded successfully
    expect(pdfPath).not.toEqual(excelPath);
  });

  test('Verify report highlights uncovered shifts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to reporting section
    await page.click('[data-testid="reports-menu"]');
    await expect(page.locator('[data-testid="report-options"]')).toBeVisible();

    // Step 2: Select shift coverage report with date range containing uncovered shifts
    await page.selectOption('[data-testid="report-type-dropdown"]', 'shift-coverage');
    await page.fill('[data-testid="from-date-input"]', '2024-02-01');
    await page.fill('[data-testid="to-date-input"]', '2024-02-15');
    await page.selectOption('[data-testid="department-filter-dropdown"]', 'Operations');

    // Step 3: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to display
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 5000 });

    // Step 4: Verify uncovered shifts are highlighted
    const uncoveredShifts = page.locator('[data-testid="uncovered-shift-row"]');
    await expect(uncoveredShifts.first()).toBeVisible();
    
    // Verify visual indicators (highlighted rows, warning icons, color coding)
    const uncoveredShiftCount = await uncoveredShifts.count();
    expect(uncoveredShiftCount).toBeGreaterThan(0);
    
    // Check for warning icons or visual indicators
    await expect(page.locator('[data-testid="uncovered-shift-icon"]').first()).toBeVisible();
    
    // Verify highlighted styling is applied
    const firstUncoveredShift = uncoveredShifts.first();
    const backgroundColor = await firstUncoveredShift.evaluate((el) => 
      window.getComputedStyle(el).backgroundColor
    );
    expect(backgroundColor).not.toBe('rgba(0, 0, 0, 0)'); // Verify some background color is applied

    // Step 5: Review details of uncovered shifts
    await uncoveredShifts.first().click();
    await expect(page.locator('[data-testid="shift-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-status"]')).toContainText('Uncovered');
    await page.click('[data-testid="close-modal-button"]');

    // Step 6: Locate and verify scheduling conflicts section
    await expect(page.locator('[data-testid="conflicts-section"]')).toBeVisible();
    const conflictRows = page.locator('[data-testid="conflict-row"]');
    const conflictCount = await conflictRows.count();
    
    // Verify conflicts are identified
    if (conflictCount > 0) {
      await expect(conflictRows.first()).toBeVisible();
      await expect(page.locator('[data-testid="conflict-icon"]').first()).toBeVisible();
    }

    // Step 7: Verify count of uncovered shifts matches summary
    const summaryUncoveredCount = await page.locator('[data-testid="summary-uncovered-count"]').textContent();
    expect(parseInt(summaryUncoveredCount || '0')).toBe(uncoveredShiftCount);
    
    // Verify conflict count in summary
    const summaryConflictCount = await page.locator('[data-testid="summary-conflict-count"]').textContent();
    expect(parseInt(summaryConflictCount || '0')).toBe(conflictCount);
    
    // Verify report accuracy indicator
    await expect(page.locator('[data-testid="report-accuracy-indicator"]')).toContainText('100%');
  });
});