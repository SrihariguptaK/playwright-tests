import { test, expect } from '@playwright/test';

test.describe('Audit Reports Generation and Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as System Administrator
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@system.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate generation of audit reports with filters', async ({ page }) => {
    // Step 1: Log in as System Administrator and verify audit reports page is accessible
    await page.click('[data-testid="audit-reports-menu"]');
    await expect(page).toHaveURL(/.*audit-reports/);
    await expect(page.locator('[data-testid="audit-reports-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Audit Reports');

    // Step 2: Select date range and user filters
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-12-31');
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-john-doe"]');
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    
    // Verify filters are applied
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Date Range: 2024-01-01 to 2024-12-31');
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('User: John Doe');
    await expect(page.locator('[data-testid="applied-filters"]')).toContainText('Status: Approved');

    // Step 3: Generate report and verify it completes within 10 seconds
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible({ timeout: 10000 });
    
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    expect(generationTime).toBeLessThan(10);
    await expect(page.locator('[data-testid="report-results-table"] tbody tr')).not.toHaveCount(0);
    await expect(page.locator('[data-testid="report-generation-success-message"]')).toContainText('Report generated successfully');
  });

  test('Verify export of audit reports in CSV and PDF', async ({ page }) => {
    // Step 1: Generate an audit report
    await page.click('[data-testid="audit-reports-menu"]');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-03-31');
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report is displayed
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-results-table"] tbody tr')).not.toHaveCount(0);

    // Step 2: Export report as CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);
    
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('CSV exported successfully');
    
    // Verify CSV file is downloaded
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Step 3: Export report as PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');
    
    // Verify PDF file is downloaded with correct formatting
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
  });

  test('Ensure scheduling of recurring audit reports', async ({ page }) => {
    // Step 1: Schedule a recurring audit report with filters
    await page.click('[data-testid="audit-reports-menu"]');
    await page.click('[data-testid="schedule-report-button"]');
    
    // Verify schedule modal is displayed
    await expect(page.locator('[data-testid="schedule-report-modal"]')).toBeVisible();
    
    // Configure report schedule
    await page.fill('[data-testid="schedule-report-name"]', 'Monthly Audit Report');
    await page.fill('[data-testid="schedule-date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="schedule-date-range-end"]', '2024-12-31');
    
    await page.click('[data-testid="schedule-user-filter-dropdown"]');
    await page.click('[data-testid="schedule-user-option-all"]');
    
    await page.click('[data-testid="schedule-status-filter-dropdown"]');
    await page.click('[data-testid="schedule-status-option-all"]');
    
    await page.click('[data-testid="schedule-frequency-dropdown"]');
    await page.click('[data-testid="schedule-frequency-monthly"]');
    
    await page.fill('[data-testid="schedule-delivery-email"]', 'admin@system.com');
    
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify schedule is saved successfully
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    await expect(page.locator('[data-testid="schedule-report-modal"]')).not.toBeVisible();
    
    // Step 2: Verify scheduled reports are generated and accessible
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduledReport = page.locator('[data-testid="scheduled-report-item"]').filter({ hasText: 'Monthly Audit Report' });
    await expect(scheduledReport).toBeVisible();
    await expect(scheduledReport.locator('[data-testid="schedule-frequency"]')).toContainText('Monthly');
    await expect(scheduledReport.locator('[data-testid="schedule-status"]')).toContainText('Active');
    
    // Verify report details
    await scheduledReport.click();
    await expect(page.locator('[data-testid="schedule-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-name"]')).toContainText('Monthly Audit Report');
    await expect(page.locator('[data-testid="schedule-next-run"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-delivery-email"]')).toContainText('admin@system.com');
  });
});