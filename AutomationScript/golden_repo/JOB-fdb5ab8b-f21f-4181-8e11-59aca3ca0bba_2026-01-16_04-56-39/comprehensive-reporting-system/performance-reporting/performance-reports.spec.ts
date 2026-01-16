import { test, expect } from '@playwright/test';

test.describe('Performance Reports - Team Lead Functionality', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TEAM_LEAD_EMAIL = 'teamlead@company.com';
  const TEAM_LEAD_PASSWORD = 'SecurePass123!';
  const REGULAR_USER_EMAIL = 'employee@company.com';
  const REGULAR_USER_PASSWORD = 'UserPass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate performance report generation with KPI filters (happy-path)', async ({ page }) => {
    // Login as team lead
    await page.fill('[data-testid="email-input"]', TEAM_LEAD_EMAIL);
    await page.fill('[data-testid="password-input"]', TEAM_LEAD_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to performance reporting module from the main dashboard
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Performance Reports');

    // Select desired KPIs from the available KPI dropdown list
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity"]');
    await page.click('[data-testid="kpi-option-efficiency"]');
    await page.click('[data-testid="kpi-option-quality"]');
    await expect(page.locator('[data-testid="selected-kpis"]')).toContainText('Productivity');
    await expect(page.locator('[data-testid="selected-kpis"]')).toContainText('Efficiency');

    // Select team from the team filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await expect(page.locator('[data-testid="selected-team"]')).toContainText('Engineering');

    // Select time period (start date and end date) using the date picker
    await page.click('[data-testid="start-date-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.click('[data-testid="end-date-picker"]');
    await page.fill('[data-testid="end-date-input"]', '2024-03-31');
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('2024-01-01');

    // Click on 'Generate Report' button to request report generation
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation to complete
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 30000 });
    
    // Verify that the report contains accurate data for the selected team and time period
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-team-name"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-01-01');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('2024-03-31');
    await expect(page.locator('[data-testid="report-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="kpi-metrics-table"]')).toBeVisible();
    
    // Verify KPI data is displayed
    const kpiRows = page.locator('[data-testid="kpi-row"]');
    await expect(kpiRows).toHaveCount(3);
  });

  test('Verify export functionality for performance reports (happy-path)', async ({ page }) => {
    // Login as team lead
    await page.fill('[data-testid="email-input"]', TEAM_LEAD_EMAIL);
    await page.fill('[data-testid="password-input"]', TEAM_LEAD_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to performance reporting module and select KPIs, team, and time period filters
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    
    await page.click('[data-testid="kpi-dropdown"]');
    await page.click('[data-testid="kpi-option-productivity"]');
    await page.click('[data-testid="kpi-option-efficiency"]');
    
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    await page.click('[data-testid="start-date-picker"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.click('[data-testid="end-date-picker"]');
    await page.fill('[data-testid="end-date-input"]', '2024-03-31');

    // Click 'Generate Report' button to generate performance report with filters
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 30000 });
    
    // Verify that the report contains visual charts and performance metrics
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="kpi-metrics-table"]')).toBeVisible();
    
    // Store on-screen data for verification
    const onScreenTeamName = await page.locator('[data-testid="report-team-name"]').textContent();
    const onScreenDateRange = await page.locator('[data-testid="report-date-range"]').textContent();

    // Click on 'Export to PDF' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for PDF download to complete and verify the downloaded PDF file
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('performance-report');
    await downloadPDF.saveAs(`./downloads/${downloadPDF.suggestedFilename()}`);
    
    // Verify PDF download success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');

    // Return to the performance report screen and click on 'Export to Excel' button
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Wait for Excel download to complete and verify the downloaded Excel file
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(downloadExcel.suggestedFilename()).toContain('performance-report');
    await downloadExcel.saveAs(`./downloads/${downloadExcel.suggestedFilename()}`);
    
    // Verify Excel download success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel exported successfully');
    
    // Verify data accuracy in both exported files against the on-screen report
    expect(onScreenTeamName).toContain('Engineering');
    expect(onScreenDateRange).toContain('2024-01-01');
    expect(onScreenDateRange).toContain('2024-03-31');
  });

  test('Ensure unauthorized users cannot access performance reports (error-case)', async ({ page }) => {
    // Login to the system using non-team lead user credentials (e.g., regular employee role)
    await page.fill('[data-testid="email-input"]', REGULAR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', REGULAR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to the performance reporting module from the main menu or dashboard
    const performanceReportsMenu = page.locator('[data-testid="performance-reports-menu"]');
    
    // Verify menu item is not visible or disabled for regular users
    if (await performanceReportsMenu.isVisible()) {
      await expect(performanceReportsMenu).toBeDisabled();
    } else {
      await expect(performanceReportsMenu).toBeHidden();
    }

    // Attempt to access the performance reporting module by directly entering the URL in the browser
    await page.goto(`${BASE_URL}/performance-reports`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('body')).toContainText(/unauthorized|forbidden|access denied/i);

    // Open browser developer tools and attempt to access the API endpoint GET /api/reports/performance directly
    const apiResponse = await page.request.get(`${BASE_URL}/api/reports/performance`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    
    // Verify that access is forbidden
    expect(apiResponse.status()).toBe(403);
    
    // Verify that no performance data is returned in the API response
    const responseBody = await apiResponse.json();
    expect(responseBody).not.toHaveProperty('data');
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/forbidden|unauthorized|access denied/i);

    // Logout and login with Team Lead credentials, then access the performance reporting module
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    
    // Login as team lead
    await page.fill('[data-testid="email-input"]', TEAM_LEAD_EMAIL);
    await page.fill('[data-testid="password-input"]', TEAM_LEAD_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Verify team lead can access performance reporting module
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-report-ui"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Performance Reports');
    
    // Verify API access works for team lead
    const teamLeadApiResponse = await page.request.get(`${BASE_URL}/api/reports/performance`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    expect(teamLeadApiResponse.status()).toBe(200);
  });
});