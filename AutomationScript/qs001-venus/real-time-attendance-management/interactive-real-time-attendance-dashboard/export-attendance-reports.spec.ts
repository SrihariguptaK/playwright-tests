import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Export Attendance Reports - Story 20', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const downloadsPath = path.join(__dirname, 'downloads');

  test.beforeEach(async ({ page }) => {
    // Login as Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance dashboard
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-dashboard-link"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
  });

  test('Validate export to PDF and Excel (happy-path)', async ({ page }) => {
    // Step 1: Apply filters on dashboard
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-engineering"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data to be displayed
    await page.waitForSelector('[data-testid="attendance-table"]');
    const filteredRows = await page.locator('[data-testid="attendance-row"]').count();
    expect(filteredRows).toBeGreaterThan(0);
    
    // Step 2: Export to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-button"]'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    // Verify PDF download
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(downloadsPath, pdfDownload.suggestedFilename());
    await pdfDownload.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    
    // Wait for export completion notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF report generated successfully');
    
    // Step 3: Export to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-button"]'),
      page.click('[data-testid="export-excel-option"]')
    ]);
    
    // Verify Excel download
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(downloadsPath, excelDownload.suggestedFilename());
    await excelDownload.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    
    // Wait for export completion notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel report generated successfully');
    
    // Cleanup
    if (fs.existsSync(pdfPath)) fs.unlinkSync(pdfPath);
    if (fs.existsSync(excelPath)) fs.unlinkSync(excelPath);
  });

  test('Verify report generation time (boundary)', async ({ page }) => {
    // Step 1: Apply filters to select a large data set
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-12-months"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-all"]');
    await page.click('[data-testid="location-filter"]');
    await page.click('[data-testid="location-all"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data to load
    await page.waitForSelector('[data-testid="attendance-table"]');
    
    // Verify large dataset is displayed
    const recordCount = await page.locator('[data-testid="total-records-count"]').textContent();
    const recordNumber = parseInt(recordCount?.replace(/[^0-9]/g, '') || '0');
    expect(recordNumber).toBeGreaterThan(1000);
    
    // Step 2: Start timer and request export
    const startTime = Date.now();
    
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Wait for report generation to complete
    await expect(page.locator('[data-testid="export-progress-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 15000 });
    
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generated within 10 seconds
    expect(generationTime).toBeLessThanOrEqual(10);
    
    // Verify download is available
    const downloadButton = page.locator('[data-testid="download-report-button"]');
    await expect(downloadButton).toBeVisible();
    await expect(downloadButton).toBeEnabled();
  });

  test('Test email delivery of reports (happy-path)', async ({ page }) => {
    // Step 1: Apply desired filters
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-sales"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data to be displayed
    await page.waitForSelector('[data-testid="attendance-table"]');
    await expect(page.locator('[data-testid="attendance-row"]').first()).toBeVisible();
    
    // Step 2: Click Export button and select format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Step 3: Select Email Report option
    await page.click('[data-testid="email-report-option"]');
    
    // Verify email dialog is displayed
    await expect(page.locator('[data-testid="email-report-dialog"]')).toBeVisible();
    
    // Step 4: Enter recipient email address
    const recipientEmail = 'stakeholder@company.com';
    await page.fill('[data-testid="recipient-email-input"]', recipientEmail);
    
    // Step 5: Add optional subject line
    await page.fill('[data-testid="email-subject-input"]', 'Attendance Report - Sales Department');
    await page.fill('[data-testid="email-message-input"]', 'Please find attached the attendance report for the Sales department.');
    
    // Step 6: Click Send button
    await page.click('[data-testid="send-email-button"]');
    
    // Step 7: Wait for email sending confirmation
    await expect(page.locator('[data-testid="email-sent-confirmation"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="email-sent-confirmation"]')).toContainText('Report sent successfully');
    await expect(page.locator('[data-testid="email-sent-confirmation"]')).toContainText(recipientEmail);
    
    // Verify dialog closes
    await expect(page.locator('[data-testid="email-report-dialog"]')).not.toBeVisible();
    
    // Verify success notification on dashboard
    await expect(page.locator('[data-testid="notification-message"]')).toContainText('Email sent to ' + recipientEmail);
  });

  test('Verify exports include applied filters and data views', async ({ page }) => {
    // Apply specific filters
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-custom"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-marketing"]');
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-present"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered data
    await page.waitForSelector('[data-testid="attendance-table"]');
    
    // Export to PDF
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Wait for export success
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    
    // Verify export metadata shows applied filters
    await page.click('[data-testid="view-export-details"]');
    await expect(page.locator('[data-testid="export-filters-summary"]')).toContainText('Date Range: 2024-01-01 to 2024-01-31');
    await expect(page.locator('[data-testid="export-filters-summary"]')).toContainText('Department: Marketing');
    await expect(page.locator('[data-testid="export-filters-summary"]')).toContainText('Status: Present');
  });

  test('Verify access control for export functionality', async ({ page, context }) => {
    // Logout as manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as non-manager user (employee)
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance dashboard
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="attendance-dashboard-link"]');
    
    // Verify export button is not visible or disabled for non-manager
    const exportButton = page.locator('[data-testid="export-button"]');
    await expect(exportButton).not.toBeVisible().catch(async () => {
      await expect(exportButton).toBeDisabled();
    });
  });
});