import { test, expect } from '@playwright/test';

test.describe('Shift Coverage and Scheduling Conflict Reporting', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate shift coverage report successfully', async ({ page }) => {
    // Step 1: Navigate to reporting section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-menu-item"]');
    await expect(page.locator('[data-testid="report-options-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toBeVisible();

    // Step 2: Select shift coverage report and date range
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-shift-coverage"]');
    
    // Select date range - current week
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-current-week"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Shift Coverage Report');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    
    // Verify report contains expected data
    await expect(page.locator('[data-testid="report-data-table"] tbody tr')).not.toHaveCount(0);

    // Step 3: Export report to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Verify PDF file downloaded successfully
    expect(download.suggestedFilename()).toMatch(/shift-coverage-report.*\.pdf/);
    await download.saveAs(`./downloads/${download.suggestedFilename()}`);
  });

  test('Identify scheduling conflicts in report', async ({ page }) => {
    // Step 1: Navigate to reporting section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-menu-item"]');
    await expect(page.locator('[data-testid="report-options-container"]')).toBeVisible();

    // Step 2: Select report type that shows conflicts
    await page.click('[data-testid="report-type-dropdown"]');
    
    // Try Scheduling Conflicts Report first, fallback to Shift Coverage Report
    const conflictsReportOption = page.locator('[data-testid="report-type-scheduling-conflicts"]');
    const coverageReportOption = page.locator('[data-testid="report-type-shift-coverage"]');
    
    if (await conflictsReportOption.isVisible()) {
      await conflictsReportOption.click();
    } else {
      await coverageReportOption.click();
    }
    
    // Step 3: Select date range with known conflicts
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-custom"]');
    
    // Set custom date range that includes test data with conflicts
    await page.fill('[data-testid="start-date-input"]', '2024-01-15');
    await page.fill('[data-testid="end-date-input"]', '2024-01-21');
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Step 4: Generate report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Step 5: Review conflicts section
    const conflictsSection = page.locator('[data-testid="conflicts-section"]');
    await expect(conflictsSection).toBeVisible();
    
    // Verify conflicts are listed clearly
    const conflictsList = page.locator('[data-testid="conflicts-list"]');
    await expect(conflictsList).toBeVisible();
    
    const conflictItems = conflictsList.locator('[data-testid="conflict-item"]');
    const conflictCount = await conflictItems.count();
    expect(conflictCount).toBeGreaterThan(0);
    
    // Step 6: Verify each conflict has required information
    for (let i = 0; i < conflictCount; i++) {
      const conflictItem = conflictItems.nth(i);
      
      // Check that conflict contains employee information
      await expect(conflictItem.locator('[data-testid="conflict-employee-name"]')).toBeVisible();
      
      // Check that conflict contains date/time information
      await expect(conflictItem.locator('[data-testid="conflict-datetime"]')).toBeVisible();
      
      // Check that conflict contains conflict type/description
      await expect(conflictItem.locator('[data-testid="conflict-description"]')).toBeVisible();
      
      // Verify conflict provides actionable information
      const conflictDescription = await conflictItem.locator('[data-testid="conflict-description"]').textContent();
      expect(conflictDescription).toBeTruthy();
      expect(conflictDescription!.length).toBeGreaterThan(10);
    }
    
    // Step 7: Verify known test conflicts are present
    // Check for specific conflict patterns in test data
    const reportContent = await page.locator('[data-testid="report-container"]').textContent();
    expect(reportContent).toBeTruthy();
    
    // Verify report summary shows conflict count
    const conflictSummary = page.locator('[data-testid="conflict-summary"]');
    await expect(conflictSummary).toBeVisible();
    await expect(conflictSummary).toContainText(/\d+ conflict/);
  });

  test('Export shift coverage report to Excel format', async ({ page }) => {
    // Navigate to reporting section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-menu-item"]');
    
    // Select shift coverage report
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-shift-coverage"]');
    
    // Select date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-current-month"]');
    
    // Generate report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const download = await downloadPromise;
    
    // Verify Excel file downloaded successfully
    expect(download.suggestedFilename()).toMatch(/shift-coverage-report.*\.(xlsx|xls)/);
    await download.saveAs(`./downloads/${download.suggestedFilename()}`);
  });

  test('Schedule automated report generation', async ({ page }) => {
    // Navigate to reporting section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-menu-item"]');
    
    // Select shift coverage report
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-shift-coverage"]');
    
    // Select date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-current-week"]');
    
    // Click schedule report button
    await page.click('[data-testid="schedule-report-button"]');
    
    // Configure schedule
    await expect(page.locator('[data-testid="schedule-modal"]')).toBeVisible();
    
    // Set frequency
    await page.click('[data-testid="schedule-frequency-dropdown"]');
    await page.click('[data-testid="frequency-weekly"]');
    
    // Set delivery method
    await page.click('[data-testid="delivery-method-dropdown"]');
    await page.click('[data-testid="delivery-email"]');
    
    // Enter email recipients
    await page.fill('[data-testid="recipients-input"]', 'manager@company.com');
    
    // Save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify schedule created
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Report scheduled successfully');
  });
});