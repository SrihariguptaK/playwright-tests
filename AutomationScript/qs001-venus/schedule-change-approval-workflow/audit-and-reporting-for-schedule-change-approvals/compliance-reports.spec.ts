import { test, expect } from '@playwright/test';

test.describe('Story-11: Compliance Reports Generation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application base URL
    await page.goto('/');
  });

  test('Generate compliance report with parameters (happy-path)', async ({ page }) => {
    // Login as auditor
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 1: Navigate to the reporting module from the main menu and locate the compliance report section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');
    await expect(page.locator('[data-testid="compliance-report-section"]')).toBeVisible();

    // Step 2: Select 'Schedule Change Approval Compliance' as the report type from the dropdown menu
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-option-schedule-change-approval"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Schedule Change Approval Compliance');

    // Step 3: Select a date range using the date picker
    const lastMonthStart = new Date();
    lastMonthStart.setMonth(lastMonthStart.getMonth() - 1);
    lastMonthStart.setDate(1);
    const lastMonthEnd = new Date();
    lastMonthEnd.setDate(0);

    await page.click('[data-testid="start-date-picker"]');
    await page.fill('[data-testid="start-date-input"]', lastMonthStart.toISOString().split('T')[0]);
    await page.click('[data-testid="end-date-picker"]');
    await page.fill('[data-testid="end-date-input"]', lastMonthEnd.toISOString().split('T')[0]);

    // Step 4: Optionally select specific departments or leave as 'All Departments', then click the 'Generate Report' button
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-all"]');
    
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await expect(page.locator('[data-testid="report-content"]')).toBeVisible({ timeout: 10000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    // Verify report generated within 10 seconds
    expect(generationTime).toBeLessThan(10000);

    // Step 5: Review the generated report content to verify it includes all required sections
    await expect(page.locator('[data-testid="report-approval-counts"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-processing-times"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-exceptions"]')).toBeVisible();

    // Step 6: Click the 'Export to PDF' button to download the report
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Verify PDF file is downloaded
    expect(download.suggestedFilename()).toContain('.pdf');
    await download.saveAs('./downloads/' + download.suggestedFilename());
  });

  test('Restrict reporting access to auditors (error-case)', async ({ page }) => {
    // Step 1: Log into the system using credentials of a non-auditor user
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Attempt to access the reporting module by navigating through the menu or entering the reporting module URL directly
    await page.click('[data-testid="main-menu"]');
    
    // Verify reporting module link is not visible for non-auditor
    const reportingLink = page.locator('[data-testid="reporting-module-link"]');
    await expect(reportingLink).not.toBeVisible();

    // Attempt direct URL access
    await page.goto('/reporting');
    
    // Verify access denied message is displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Step 3: Log out from the non-auditor account completely
    await page.click('[data-testid="user-profile"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Step 4: Log back into the system using valid auditor credentials
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 5: Navigate to the reporting module using the menu or direct URL
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');
    
    // Verify access granted for auditor
    await expect(page.locator('[data-testid="compliance-report-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toBeVisible();
  });

  test('Generate compliance report with parameters - verify all acceptance criteria', async ({ page }) => {
    // Login as auditor
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Navigate to reporting module
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-module-link"]');

    // Select report parameters
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-option-schedule-change-approval"]');
    
    await page.click('[data-testid="start-date-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.click('[data-testid="end-date-picker"]');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');

    // Generate report and measure time
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-content"]')).toBeVisible({ timeout: 10000 });
    const endTime = Date.now();
    
    // AC#1: System generates compliance reports based on selected parameters
    await expect(page.locator('[data-testid="report-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-31');

    // AC#2: Reports include approval counts, processing times, and exception details
    await expect(page.locator('[data-testid="report-approval-counts"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-processing-times"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-exceptions"]')).toBeVisible();

    // AC#3: Reports can be exported in PDF and Excel formats
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeVisible();

    // Test PDF export
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toMatch(/\.pdf$/);

    // Test Excel export
    const excelDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const excelDownload = await excelDownloadPromise;
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);

    // AC#4: Report generation completes within 10 seconds
    const generationTime = endTime - startTime;
    expect(generationTime).toBeLessThan(10000);
  });

  test('Restrict reporting access to auditors - verify AC#5', async ({ page }) => {
    // Test with non-auditor user
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // AC#5: Access to reporting module is restricted to auditors
    await page.goto('/reporting');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Logout and login as auditor
    await page.click('[data-testid="user-profile"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123');
    await page.click('[data-testid="login-button"]');
    
    // Verify auditor can access
    await page.goto('/reporting');
    await expect(page.locator('[data-testid="compliance-report-section"]')).toBeVisible();
  });
});