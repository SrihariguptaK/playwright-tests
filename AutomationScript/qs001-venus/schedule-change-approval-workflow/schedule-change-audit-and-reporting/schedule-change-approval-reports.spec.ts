import { test, expect } from '@playwright/test';

test.describe('Schedule Change Approval Reports - Story 20', () => {
  const adminUser = {
    username: 'admin@company.com',
    password: 'AdminPass123!'
  };

  const nonAdminUser = {
    username: 'employee@company.com',
    password: 'EmployeePass123!'
  };

  test('Generate approval summary report with filters (happy-path)', async ({ page }) => {
    // Log in as an administrator user with reporting access permissions
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', adminUser.username);
    await page.fill('[data-testid="password-input"]', adminUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the reporting portal or reports section from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reports-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Select 'Approval Summary Report' from the report type dropdown menu
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="approval-summary-report-option"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Approval Summary Report');

    // Set the date range filter to cover the last 30 days by selecting start and end dates
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);

    // Select a specific department from the department filter dropdown (e.g., 'Engineering')
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-engineering-option"]');
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toContainText('Engineering');

    // Select a specific approver from the approver filter dropdown
    await page.click('[data-testid="approver-filter-dropdown"]');
    await page.click('[data-testid="approver-option"]').first();

    // Click the 'Generate Report' button to create the filtered report
    await page.click('[data-testid="generate-report-button"]');

    // Wait for report generation to complete (should be within 10 seconds per SLA)
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });

    // Verify the report data matches the applied filters (date range, department, approver)
    await expect(page.locator('[data-testid="report-filters-summary"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="report-date-range"]')).toBeVisible();

    // Scroll down to view the visual dashboard section with charts and statistics
    await page.locator('[data-testid="visual-dashboard-section"]').scrollIntoViewIfNeeded();

    // Verify the bar chart showing approval volumes over time reflects the filtered data accurately
    await expect(page.locator('[data-testid="approval-volumes-chart"]')).toBeVisible();
    const barChartData = await page.locator('[data-testid="approval-volumes-chart"]').getAttribute('data-chart-values');
    expect(barChartData).toBeTruthy();

    // Verify the pie chart showing approval outcomes (approved, rejected, pending) reflects accurate percentages
    await expect(page.locator('[data-testid="approval-outcomes-chart"]')).toBeVisible();
    const pieChartData = await page.locator('[data-testid="approval-outcomes-chart"]').getAttribute('data-chart-values');
    expect(pieChartData).toBeTruthy();

    // Verify the average approval time statistic is calculated correctly
    await expect(page.locator('[data-testid="average-approval-time"]')).toBeVisible();
    const avgTimeText = await page.locator('[data-testid="average-approval-time"]').textContent();
    expect(avgTimeText).toMatch(/\d+/);

    // Click the 'Export' button and select 'CSV' format from the export options
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');

    // Confirm the CSV export and download the file
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const csvDownload = await downloadPromise;
    expect(csvDownload.suggestedFilename()).toContain('.csv');

    // Open the downloaded CSV file in a spreadsheet application
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Verify CSV file contains complete data matching the filtered report results
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('Engineering');
    expect(csvContent.length).toBeGreaterThan(0);

    // Return to the reporting interface and click 'Export' button again, this time selecting 'PDF' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');

    // Confirm the PDF export and download the file
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');

    // Open the downloaded PDF file in a PDF reader
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Verify PDF contains all report elements: summary statistics, data table, and visual charts
    const pdfStats = await pdfDownload.createReadStream();
    expect(pdfStats).toBeTruthy();

    // Verify the visual charts in the PDF match the charts displayed in the web interface
    // Note: Full PDF content verification would require additional PDF parsing libraries
    expect(await pdfDownload.suggestedFilename()).toMatch(/approval.*summary/i);
  });

  test('Restrict report access to administrators (error-case)', async ({ page, request }) => {
    // Log in as a non-administrator user (regular employee or approver without admin privileges)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminUser.username);
    await page.fill('[data-testid="password-input"]', nonAdminUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the reporting portal by entering the reports URL directly
    await page.goto('/admin/reports');
    
    // Verify access is denied with error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access.*denied|unauthorized|permission/i);

    // Check the main navigation menu for any reporting or reports links
    await page.click('[data-testid="main-menu"]');
    const reportsLink = page.locator('[data-testid="reports-link"]');
    await expect(reportsLink).not.toBeVisible();

    // Attempt to access the approval summary report API endpoint directly using non-admin token
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';

    const summaryResponse = await request.get('/api/reports/approval-summary', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(summaryResponse.status()).toBe(403);
    const summaryBody = await summaryResponse.json();
    expect(summaryBody.error || summaryBody.message).toMatch(/unauthorized|forbidden|access.*denied/i);

    // Attempt to access report export functionality via API using non-admin token
    const exportResponse = await request.get('/api/reports/export', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(exportResponse.status()).toBe(403);
    const exportBody = await exportResponse.json();
    expect(exportBody.error || exportBody.message).toMatch(/unauthorized|forbidden|access.*denied/i);

    // Log out from the non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log in as an administrator user with proper reporting access permissions
    await page.fill('[data-testid="username-input"]', adminUser.username);
    await page.fill('[data-testid="password-input"]', adminUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check the main navigation menu for reporting or reports links
    await page.click('[data-testid="main-menu"]');
    const adminReportsLink = page.locator('[data-testid="reports-link"]');
    await expect(adminReportsLink).toBeVisible();

    // Click on the reports link to navigate to the reporting portal
    await page.click('[data-testid="reports-link"]');
    await expect(page).toHaveURL(/.*reports/);

    // Verify all reporting features are accessible: report type dropdown, filter options, generate button, and export functionality
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="approver-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();

    // Select 'Approval Summary Report' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="approval-summary-report-option"]');

    // Apply a date range filter and click 'Generate Report' button
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 7);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });

    // Test export functionality by clicking 'Export' and selecting CSV format
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-csv-option"]')).toBeVisible();
    await page.click('[data-testid="export-csv-option"]');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');

    // Verify administrator can access reporting API endpoint using admin authentication token
    const adminCookies = await page.context().cookies();
    const adminAuthToken = adminCookies.find(c => c.name === 'auth_token')?.value || '';

    const adminSummaryResponse = await request.get('/api/reports/approval-summary', {
      headers: {
        'Authorization': `Bearer ${adminAuthToken}`
      }
    });
    expect(adminSummaryResponse.status()).toBe(200);
    const adminSummaryBody = await adminSummaryResponse.json();
    expect(adminSummaryBody).toBeTruthy();

    // Verify administrator can access export API endpoint using admin authentication token
    const adminExportResponse = await request.get('/api/reports/export', {
      headers: {
        'Authorization': `Bearer ${adminAuthToken}`
      }
    });
    expect(adminExportResponse.status()).toBe(200);
  });
});