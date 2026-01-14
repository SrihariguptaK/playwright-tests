import { test, expect } from '@playwright/test';

test.describe('Schedule Change Approval Reports - Manager Reporting', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate report generation with filters (happy-path)', async ({ page }) => {
    // Step 1: Manager navigates to the reporting portal from the main dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-portal-link"]');
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();

    // Step 2: Manager clicks on 'Schedule Change Approval Reports' menu option
    await page.click('[data-testid="schedule-change-approval-reports-menu"]');
    await expect(page).toHaveURL(/.*reports\/schedule-change-approvals/);
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();

    // Step 3: Manager selects a specific department from the department filter dropdown
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Engineering');

    // Step 4: Manager selects a date range (e.g., last 30 days) using the date range picker
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await expect(page.locator('[data-testid="date-range-picker"]')).toContainText('Last 30 days');

    // Wait for report to update after filters are applied
    await page.waitForResponse(response => 
      response.url().includes('/api/reports/schedule-change-approvals') && response.status() === 200
    );

    // Step 5: Manager reviews the updated charts section displaying approval metrics
    await expect(page.locator('[data-testid="charts-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-times-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-volumes-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-status-chart"]')).toBeVisible();

    // Step 6: Manager scrolls down to view the data tables section
    await page.locator('[data-testid="data-tables-section"]').scrollIntoViewIfNeeded();
    await expect(page.locator('[data-testid="data-tables-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-data-table"]')).toBeVisible();

    // Step 7: Manager verifies the total count of records displayed matches the filter criteria
    const recordCount = await page.locator('[data-testid="total-records-count"]').textContent();
    expect(recordCount).toBeTruthy();
    expect(parseInt(recordCount || '0')).toBeGreaterThan(0);
    
    // Verify data is accurate and visualizations render correctly
    const tableRows = await page.locator('[data-testid="approval-data-table"] tbody tr').count();
    expect(tableRows).toBeGreaterThan(0);
  });

  test('Verify report export functionality (happy-path)', async ({ page }) => {
    // Navigate to reporting dashboard
    await page.goto('/reports/schedule-change-approvals');
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();

    // Step 1: Manager applies desired filters and generates a report with visible data
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]');
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    await page.waitForResponse(response => 
      response.url().includes('/api/reports/schedule-change-approvals') && response.status() === 200
    );
    
    await expect(page.locator('[data-testid="approval-data-table"]')).toBeVisible();

    // Step 2: Manager locates and clicks the 'Export' button in the report toolbar
    await page.locator('[data-testid="export-button"]').scrollIntoViewIfNeeded();
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown-menu"]')).toBeVisible();

    // Step 3: Manager selects 'Export as PDF' from the dropdown menu
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-as-pdf-option"]');
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');

    // Step 4: Manager opens the downloaded PDF file (verify download completed)
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Step 5: Manager returns to the reporting dashboard and clicks the 'Export' button again
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dropdown-menu"]')).toBeVisible();

    // Step 6: Manager selects 'Export as Excel' from the dropdown menu
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-as-excel-option"]');
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);

    // Step 7: Manager opens the downloaded Excel file (verify download completed)
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
  });

  test('Ensure unauthorized users cannot access reports (error-case)', async ({ page }) => {
    // Logout manager and login as non-manager user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Non-manager user attempts to navigate to the reporting portal from the main dashboard menu
    await page.click('[data-testid="main-menu"]');
    
    // Verify reporting portal link is not visible for non-manager
    const reportingPortalLink = page.locator('[data-testid="reporting-portal-link"]');
    await expect(reportingPortalLink).not.toBeVisible();

    // Step 2: Non-manager user attempts to directly access the reporting dashboard by entering the URL
    await page.goto('/reports/schedule-change-approvals');
    
    // Step 3: Non-manager user views the error message displayed on the screen
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-message-text"]')).toContainText('You do not have permission to access this resource');
    
    // Verify user is redirected or stays on error page
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/\/(access-denied|unauthorized|reports\/schedule-change-approvals)/);

    // Step 4: Non-manager user attempts to access the reporting API endpoint directly
    const apiResponse = await page.request.get('/api/reports/schedule-change-approvals');
    expect(apiResponse.status()).toBe(403);
    
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Step 5: Non-manager user verifies they can still access other authorized areas
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();
    
    await page.goto('/profile');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();
  });
});