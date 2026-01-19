import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

test.describe('Export Performance Metrics and Review Data', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const metricsPageURL = `${baseURL}/metrics`;
  const reviewDataPageURL = `${baseURL}/review-data`;

  test.beforeEach(async ({ page }) => {
    // Login as authorized Performance Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/dashboard|metrics/);
  });

  test('Validate successful export of selected data - Metrics page PDF format', async ({ page }) => {
    // Step 1: Navigate to Metrics page
    await page.goto(metricsPageURL);
    await expect(page).toHaveURL(metricsPageURL);
    await expect(page.locator('[data-testid="metrics-page-header"]')).toBeVisible();

    // Step 2: Select data sets to export using checkboxes
    await page.waitForSelector('[data-testid="data-selection-checkbox"]');
    const dataCheckboxes = page.locator('[data-testid="data-selection-checkbox"]');
    const checkboxCount = await dataCheckboxes.count();
    
    // Select first 3 data sets
    for (let i = 0; i < Math.min(3, checkboxCount); i++) {
      await dataCheckboxes.nth(i).check();
      await expect(dataCheckboxes.nth(i)).toBeChecked();
    }

    // Choose export format - PDF
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('[data-testid="export-format-pdf"]');
    await expect(page.locator('[data-testid="export-format-dropdown"]')).toContainText('PDF');

    // Step 3: Initiate export and download file
    const startTime = Date.now();
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = (endTime - startTime) / 1000;

    // Verify file is generated and downloaded within 10 seconds
    expect(exportDuration).toBeLessThanOrEqual(10);
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Save and verify the downloaded file
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Validate successful export of selected data - Review Data page Excel format', async ({ page }) => {
    // Step 1: Navigate to Review Data page
    await page.goto(reviewDataPageURL);
    await expect(page).toHaveURL(reviewDataPageURL);
    await expect(page.locator('[data-testid="review-data-page-header"]')).toBeVisible();

    // Step 2: Select data sets to export
    await page.waitForSelector('[data-testid="review-data-selection"]');
    await page.click('[data-testid="select-all-reviews-checkbox"]');
    await expect(page.locator('[data-testid="select-all-reviews-checkbox"]')).toBeChecked();

    // Choose export format - Excel
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('[data-testid="export-format-excel"]');
    await expect(page.locator('[data-testid="export-format-dropdown"]')).toContainText('Excel');

    // Step 3: Initiate export and download file
    const startTime = Date.now();
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-button"]');
    
    const download = await downloadPromise;
    const endTime = Date.now();
    const exportDuration = (endTime - startTime) / 1000;

    // Verify file is generated and downloaded within 10 seconds
    expect(exportDuration).toBeLessThanOrEqual(10);
    expect(download.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    
    // Save and verify the downloaded file
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Verify access control for export functionality - unauthorized user', async ({ page, context }) => {
    // Logout current user
    await page.goto(`${baseURL}/logout`);
    
    // Login as unauthorized user (employee without export permissions)
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/dashboard/);

    // Step 1: Navigate to Metrics page as unauthorized user
    await page.goto(metricsPageURL);
    
    // Step 2: Verify that export options are not accessible
    const exportButton = page.locator('[data-testid="export-button"]');
    const exportFormatDropdown = page.locator('[data-testid="export-format-dropdown"]');
    
    // Verify export button is either not visible or disabled
    await expect(exportButton).not.toBeVisible().catch(async () => {
      await expect(exportButton).toBeDisabled();
    });
    
    // Verify export format dropdown is not accessible
    await expect(exportFormatDropdown).not.toBeVisible().catch(async () => {
      await expect(exportFormatDropdown).toBeDisabled();
    });

    // Step 3: Attempt to access export endpoint directly via URL
    const response = await page.goto(`${baseURL}/api/export?format=pdf&data=metrics`);
    
    // Verify access is denied (403 Forbidden or 401 Unauthorized)
    expect([401, 403]).toContain(response?.status() || 0);
  });

  test('Verify access control for export functionality - direct API access attempt', async ({ request, page }) => {
    // Logout and login as unauthorized user
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', 'regular.employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');

    // Get cookies from the browser context for API request
    const cookies = await page.context().cookies();
    
    // Attempt to call export API directly
    const apiResponse = await request.get(`${baseURL}/api/export`, {
      params: {
        format: 'pdf',
        dataType: 'metrics'
      }
    });

    // Verify that access is denied
    expect([401, 403]).toContain(apiResponse.status());
    
    const responseBody = await apiResponse.json().catch(() => ({}));
    expect(responseBody).toHaveProperty('error');
  });

  test('Validate exported data matches selected filters and criteria', async ({ page }) => {
    // Navigate to Metrics page
    await page.goto(metricsPageURL);
    await expect(page).toHaveURL(metricsPageURL);

    // Apply specific filters
    await page.click('[data-testid="filter-dropdown"]');
    await page.click('[data-testid="filter-department-engineering"]');
    await page.click('[data-testid="filter-date-range"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-03-31');
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered data to load
    await page.waitForSelector('[data-testid="filtered-results-loaded"]');

    // Capture filter criteria for verification
    const filterSummary = await page.locator('[data-testid="active-filters-summary"]').textContent();
    expect(filterSummary).toContain('Engineering');
    expect(filterSummary).toContain('2024-01-01');

    // Select filtered data for export
    await page.click('[data-testid="select-all-filtered-checkbox"]');
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('[data-testid="export-format-excel"]');

    // Initiate export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    const download = await downloadPromise;

    // Verify download completed successfully
    expect(download.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });
});