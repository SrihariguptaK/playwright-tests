import { test, expect } from '@playwright/test';

test.describe('Risk Factor Summary Reports - Story 8', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as Risk Analyst
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'riskanalyst01');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate generation of risk factor summary report with filters', async ({ page }) => {
    // Action: Access risk report module and select filters
    await page.click('[data-testid="risk-report-module"]');
    await expect(page).toHaveURL(/.*reports\/riskfactors/);
    
    // Select date range filter (last 30 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    
    // Select risk level filter (High, Medium)
    await page.click('[data-testid="risk-level-filter"]');
    await page.check('[data-testid="risk-level-high"]');
    await page.check('[data-testid="risk-level-medium"]');
    
    // Select status filter (Active, Pending)
    await page.click('[data-testid="status-filter"]');
    await page.check('[data-testid="status-active"]');
    await page.check('[data-testid="status-pending"]');
    
    // Click Generate Report button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Filters applied and report generated
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Report Generated Successfully');
    
    // Action: Review report data for accuracy
    const reportTable = page.locator('[data-testid="report-table"]');
    await expect(reportTable).toBeVisible();
    
    // Verify report contains applicant names
    await expect(reportTable.locator('[data-testid="applicant-name-column"]').first()).toBeVisible();
    
    // Verify risk categories are displayed
    await expect(reportTable.locator('[data-testid="risk-category-column"]').first()).toBeVisible();
    
    // Verify risk levels match filter (High or Medium)
    const riskLevelCells = await reportTable.locator('[data-testid="risk-level-cell"]').allTextContents();
    for (const level of riskLevelCells) {
      expect(['High', 'Medium']).toContain(level.trim());
    }
    
    // Verify status matches filter (Active or Pending)
    const statusCells = await reportTable.locator('[data-testid="status-cell"]').allTextContents();
    for (const status of statusCells) {
      expect(['Active', 'Pending']).toContain(status.trim());
    }
    
    // Expected Result: Report data matches filtered criteria
    await expect(page.locator('[data-testid="report-summary"]')).toContainText(/Total Records: \d+/);
    
    // Action: Export report in PDF format
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF exported successfully
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Action: Export report in Excel format
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel exported successfully and is readable
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
  });

  test('Verify scheduling of automated report generation', async ({ page }) => {
    // Navigate to the risk report module
    await page.click('[data-testid="risk-report-module"]');
    await expect(page).toHaveURL(/.*reports\/riskfactors/);
    
    // Action: Schedule automated risk report generation
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();
    
    // Enter report name
    await page.fill('[data-testid="report-name-input"]', 'Weekly Risk Summary');
    
    // Select report filters
    await page.click('[data-testid="schedule-date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    
    await page.click('[data-testid="schedule-risk-level-filter"]');
    await page.click('[data-testid="risk-level-all-option"]');
    
    await page.click('[data-testid="schedule-status-filter"]');
    await page.click('[data-testid="status-active-option"]');
    
    // Set recurrence pattern
    await page.click('[data-testid="recurrence-pattern-dropdown"]');
    await page.click('[data-testid="recurrence-weekly-option"]');
    
    await page.click('[data-testid="recurrence-day-dropdown"]');
    await page.click('[data-testid="recurrence-monday-option"]');
    
    // Set time for report generation
    await page.fill('[data-testid="schedule-time-input"]', '08:00');
    await page.selectOption('[data-testid="schedule-time-period"]', 'AM');
    
    // Select export format
    await page.check('[data-testid="export-format-pdf"]');
    await page.check('[data-testid="export-format-excel"]');
    
    // Enter delivery email
    await page.fill('[data-testid="recipient-email-input"]', 'analyst@company.com');
    
    // Click Save Schedule button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule saved and confirmation displayed
    await expect(page.locator('[data-testid="schedule-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-confirmation-message"]')).toContainText('Schedule saved successfully');
    
    // Verify the scheduled report appears in the list
    await page.click('[data-testid="view-scheduled-reports-link"]');
    const scheduledReportsList = page.locator('[data-testid="scheduled-reports-list"]');
    await expect(scheduledReportsList).toBeVisible();
    
    const scheduledReport = scheduledReportsList.locator('text=Weekly Risk Summary');
    await expect(scheduledReport).toBeVisible();
    
    // Verify schedule details
    const reportRow = page.locator('[data-testid="scheduled-report-row"]', { hasText: 'Weekly Risk Summary' });
    await expect(reportRow.locator('[data-testid="recurrence-info"]')).toContainText('Weekly - Monday');
    await expect(reportRow.locator('[data-testid="schedule-time-info"]')).toContainText('08:00 AM');
    
    // Action: Verify report generation at scheduled time
    // Check execution log
    await page.click('[data-testid="execution-log-tab"]');
    const executionLog = page.locator('[data-testid="execution-log-table"]');
    await expect(executionLog).toBeVisible();
    
    // Expected Result: Report generated and delivered as per schedule
    // Verify the scheduled report entry exists in execution history
    await expect(page.locator('[data-testid="scheduled-report-status"]').first()).toContainText(/Scheduled|Pending|Completed/);
  });

  test('Test access control for risk reports - unauthorized user', async ({ page }) => {
    // Logout from Risk Analyst session
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Action: Login as unauthorized user
    await page.fill('[data-testid="username-input"]', 'testuser');
    await page.fill('[data-testid="password-input"]', 'TestPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Action: Attempt to navigate to risk report module via menu
    const riskReportMenu = page.locator('[data-testid="risk-report-module"]');
    
    // Expected Result: Menu item should not be visible or accessible
    if (await riskReportMenu.isVisible()) {
      await riskReportMenu.click();
      // Should show access denied message
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|Permission/);
    }
    
    // Action: Attempt to access risk report module directly by URL
    await page.goto('/api/reports/riskfactors');
    
    // Expected Result: Access denied with appropriate error
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/Access Denied|Unauthorized|403|Permission/);
    
    // Verify no report data is displayed
    await expect(page.locator('[data-testid="report-table"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="report-container"]')).not.toBeVisible();
    
    // Verify error is logged (check for error indicator)
    await expect(page.locator('[data-testid="unauthorized-access-indicator"]')).toBeVisible();
  });

  test('Test access control for risk reports - authorized Risk Analyst', async ({ page }) => {
    // Already logged in as Risk Analyst from beforeEach hook
    
    // Action: Navigate to risk report module via menu
    await page.click('[data-testid="risk-report-module"]');
    
    // Expected Result: Access granted and reports displayed
    await expect(page).toHaveURL(/.*reports\/riskfactors/);
    await expect(page.locator('[data-testid="risk-report-page-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-report-page-title"]')).toContainText('Risk Factor Summary Reports');
    
    // Action: Generate a sample risk report without filters
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report generated successfully
    await expect(page.locator('[data-testid="report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-table"]')).toBeVisible();
    
    // Verify all report features are accessible
    // Filters
    await expect(page.locator('[data-testid="date-range-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="risk-level-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-filter"]')).toBeVisible();
    
    // Export buttons
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeEnabled();
    
    // Scheduling
    await expect(page.locator('[data-testid="schedule-report-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-report-button"]')).toBeEnabled();
    
    // Verify report data is displayed
    const reportRows = page.locator('[data-testid="report-table"] tbody tr');
    const rowCount = await reportRows.count();
    expect(rowCount).toBeGreaterThan(0);
  });
});