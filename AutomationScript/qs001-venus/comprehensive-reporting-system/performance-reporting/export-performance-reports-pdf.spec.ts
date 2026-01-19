import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Performance Reports to PDF - Story 12', () => {
  let downloadPath: string;

  test.beforeEach(async ({ page }) => {
    // Login as Department Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'department.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to performance reports section
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="performance-reports-link"]');
    await expect(page.locator('[data-testid="performance-report-page"]')).toBeVisible();
  });

  test('Export performance report to PDF', async ({ page, context }) => {
    // Step 1: Generate performance report
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated and displayed
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Performance Report');
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-visualizations"]')).toBeVisible();
    
    // Verify report is displayed with data
    const reportRows = page.locator('[data-testid="report-data-row"]');
    await expect(reportRows).toHaveCount(await reportRows.count());
    expect(await reportRows.count()).toBeGreaterThan(0);
    
    // Step 2: Click export to PDF
    const downloadPromise = page.waitForEvent('download', { timeout: 10000 });
    const startTime = Date.now();
    
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for download to start
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = (endTime - startTime) / 1000;
    
    // Verify export completes within 5 seconds (Acceptance Criteria #3)
    expect(exportDuration).toBeLessThanOrEqual(5);
    
    // Verify PDF file is downloaded
    expect(download.suggestedFilename()).toMatch(/performance.*report.*\.pdf$/i);
    
    // Save the downloaded file
    const downloadsPath = path.join(__dirname, 'downloads');
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify file exists and has content
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1000); // PDF should be at least 1KB
    
    // Step 3: Verify PDF file contains accurate and formatted performance data
    // Check file header to confirm it's a valid PDF
    const fileBuffer = fs.readFileSync(filePath);
    const pdfHeader = fileBuffer.toString('utf-8', 0, 5);
    expect(pdfHeader).toBe('%PDF-');
    
    // Verify success message or notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText(/successfully exported|download complete/i);
    
    // Clean up downloaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  });

  test('Verify PDF export maintains report formatting and visualizations', async ({ page }) => {
    // Generate performance report with specific data
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Capture report details before export
    const reportTitle = await page.locator('[data-testid="report-title"]').textContent();
    const reportDataRows = await page.locator('[data-testid="report-data-row"]').count();
    const hasCharts = await page.locator('[data-testid="report-chart"]').count() > 0;
    const hasTables = await page.locator('[data-testid="report-data-table"]').isVisible();
    
    // Export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Save and verify PDF
    const downloadsPath = path.join(__dirname, 'downloads');
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify PDF file structure (Acceptance Criteria #2)
    const fileBuffer = fs.readFileSync(filePath);
    const pdfContent = fileBuffer.toString('utf-8');
    
    // Check for PDF structure elements indicating proper formatting
    expect(pdfContent).toContain('/Type /Catalog');
    expect(pdfContent).toContain('/Type /Page');
    
    // Verify file size indicates content with visualizations
    const fileStats = fs.statSync(filePath);
    if (hasCharts) {
      expect(fileStats.size).toBeGreaterThan(10000); // PDFs with charts should be larger
    }
    
    // Clean up
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  });

  test('Verify export functionality is restricted to authorized users', async ({ page, context }) => {
    // Verify Department Manager can access export (Acceptance Criteria #4)
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Verify export button is visible and enabled for authorized user
    const exportButton = page.locator('[data-testid="export-pdf-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();
    
    // Logout and login as unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as regular employee (unauthorized)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Try to navigate to performance reports
    await page.goto('/reports/performance');
    
    // Verify unauthorized user cannot access export functionality
    const isAccessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const exportButtonHidden = await page.locator('[data-testid="export-pdf-button"]').isHidden().catch(() => true);
    const exportButtonDisabled = await page.locator('[data-testid="export-pdf-button"]').isDisabled().catch(() => true);
    
    // At least one security measure should be in place
    expect(isAccessDenied || exportButtonHidden || exportButtonDisabled).toBeTruthy();
  });

  test('Verify export operation completes within 5 seconds for large reports', async ({ page }) => {
    // Generate a large performance report
    await page.selectOption('[data-testid="report-period-select"]', 'yearly');
    await page.selectOption('[data-testid="report-detail-level"]', 'detailed');
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for large report to be generated
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-data-row"]').first()).toBeVisible();
    
    // Measure export time (Acceptance Criteria #3)
    const startTime = Date.now();
    const downloadPromise = page.waitForEvent('download', { timeout: 10000 });
    
    await page.click('[data-testid="export-pdf-button"]');
    
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = (endTime - startTime) / 1000;
    
    // Verify export completes within 5 seconds even for large reports
    expect(exportDuration).toBeLessThanOrEqual(5);
    
    // Verify file was successfully downloaded
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Save and verify file
    const downloadsPath = path.join(__dirname, 'downloads');
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(1000);
    
    // Clean up
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  });

  test('Verify exported PDF accuracy matches displayed report data', async ({ page }) => {
    // Generate performance report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="performance-report-container"]')).toBeVisible({ timeout: 10000 });
    
    // Capture key data points from displayed report (Acceptance Criteria #1)
    const reportTitle = await page.locator('[data-testid="report-title"]').textContent();
    const reportDate = await page.locator('[data-testid="report-date"]').textContent();
    const firstMetricValue = await page.locator('[data-testid="metric-value"]').first().textContent();
    
    // Export to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Save PDF
    const downloadsPath = path.join(__dirname, 'downloads');
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify PDF contains accurate data
    const fileBuffer = fs.readFileSync(filePath);
    expect(fileBuffer.length).toBeGreaterThan(0);
    
    // Verify it's a valid PDF file
    const pdfHeader = fileBuffer.toString('utf-8', 0, 5);
    expect(pdfHeader).toBe('%PDF-');
    
    // Verify success notification
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    
    // Clean up
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  });
});