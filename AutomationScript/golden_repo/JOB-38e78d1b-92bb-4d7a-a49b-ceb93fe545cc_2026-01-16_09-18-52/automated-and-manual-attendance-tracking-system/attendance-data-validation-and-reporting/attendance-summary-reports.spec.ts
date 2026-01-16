import { test, expect } from '@playwright/test';

test.describe('Attendance Summary Reports - Story 29', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application login page
    await page.goto('/login');
  });

  test('Validate attendance summary report generation (happy-path)', async ({ page }) => {
    // Login as authorized manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 1: Navigate to attendance reports module from the main dashboard
    await page.click('[data-testid="attendance-reports-menu"]');
    
    // Expected Result: Report interface is displayed
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    
    // Step 2: Select a specific department from the department dropdown
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Step 3: Select a date range (e.g., last 30 days) using the date picker
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="preset-last-30-days"]');
    
    // Step 4: Click the 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-loading"]', { state: 'hidden', timeout: 10000 });
    
    // Expected Result: Report is generated with accurate data and visualizations
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-metrics-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-chart"]')).toBeVisible();
    
    // Step 5: Review the generated report data and verify metrics accuracy
    const totalHours = await page.locator('[data-testid="metric-total-hours"]').textContent();
    const absences = await page.locator('[data-testid="metric-absences"]').textContent();
    const lateArrivals = await page.locator('[data-testid="metric-late-arrivals"]').textContent();
    
    expect(totalHours).toBeTruthy();
    expect(absences).toBeTruthy();
    expect(lateArrivals).toBeTruthy();
    
    // Verify report contains data rows
    const reportRows = await page.locator('[data-testid="report-data-row"]').count();
    expect(reportRows).toBeGreaterThan(0);
    
    // Step 6: Click the 'Export as PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file downloads successfully with correct content
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('attendance');
    
    // Step 7: Click the 'Export as Excel' button
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel file downloads successfully with correct content
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(excelDownload.suggestedFilename()).toContain('attendance');
  });

  test('Ensure access control for attendance reports (error-case)', async ({ page }) => {
    // Step 1: Navigate to the login page and enter credentials for an unauthorized user
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 2: Verify that the attendance reports menu option is not visible
    const reportsMenuVisible = await page.locator('[data-testid="attendance-reports-menu"]').isVisible().catch(() => false);
    expect(reportsMenuVisible).toBe(false);
    
    // Step 3: Attempt to navigate to the attendance reports module by entering the URL directly
    await page.goto('/attendance/reports');
    
    // Expected Result: Access to reports is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    const deniedMessage = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(deniedMessage).toContain('Access Denied');
    
    // Alternative check: verify redirect to unauthorized page or dashboard
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/attendance/reports');
    
    // Step 4: Logout from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Wait for logout to complete
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    
    // Step 5: Navigate to the login page and enter credentials for an authorized manager account
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Step 6: Navigate to the attendance reports module from the main dashboard
    await page.click('[data-testid="attendance-reports-menu"]');
    
    // Expected Result: Access to reports is granted
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    
    // Step 7: Verify that all report features are accessible
    await expect(page.locator('[data-testid="department-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeVisible();
    
    // Verify filters are functional
    await page.click('[data-testid="department-dropdown"]');
    await expect(page.locator('[data-testid="department-option-engineering"]')).toBeVisible();
  });

  test('Validate report generation performance within 10 seconds', async ({ page }) => {
    // Login as authorized manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to attendance reports module
    await page.click('[data-testid="attendance-reports-menu"]');
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    
    // Select parameters
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="preset-last-30-days"]');
    
    // Measure report generation time
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await page.waitForSelector('[data-testid="report-loading"]', { state: 'hidden', timeout: 10000 });
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Expected Result: Report generation time under 10 seconds
    expect(generationTime).toBeLessThan(10);
  });

  test('Validate graphical visualizations of attendance metrics', async ({ page }) => {
    // Login as authorized manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to attendance reports module
    await page.click('[data-testid="attendance-reports-menu"]');
    await expect(page.locator('[data-testid="attendance-reports-interface"]')).toBeVisible();
    
    // Select parameters and generate report
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="preset-last-30-days"]');
    await page.click('[data-testid="generate-report-button"]');
    
    await page.waitForSelector('[data-testid="report-loading"]', { state: 'hidden', timeout: 10000 });
    
    // Expected Result: System provides graphical visualizations
    await expect(page.locator('[data-testid="attendance-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="absences-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-arrivals-chart"]')).toBeVisible();
    
    // Verify chart elements are rendered
    const chartCanvas = await page.locator('[data-testid="attendance-chart"] canvas').count();
    expect(chartCanvas).toBeGreaterThan(0);
  });
});