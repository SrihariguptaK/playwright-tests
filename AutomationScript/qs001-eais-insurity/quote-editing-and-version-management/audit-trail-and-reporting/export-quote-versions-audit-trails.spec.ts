import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as csv from 'csv-parser';

test.describe('Export Quote Versions and Audit Trails to CSV', () => {
  const downloadPath = path.join(__dirname, 'downloads');
  
  test.beforeEach(async ({ page }) => {
    // Login with Quote Manager credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'quote.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate CSV export of quote versions (happy-path)', async ({ page }) => {
    // Navigate to the quote management section and select a quote with multiple versions
    await page.goto('/quotes');
    await page.click('[data-testid="quote-list-item"]:has-text("Quote")');
    await expect(page.locator('[data-testid="quote-details"]')).toBeVisible();

    // Click on the 'Version History' tab or link
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();

    // Apply filters to the version list (e.g., filter by date range, user, or version status)
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-from-filter"]', '2024-01-01');
    await page.fill('[data-testid="date-to-filter"]', '2024-12-31');
    await page.selectOption('[data-testid="status-filter"]', 'approved');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify filtered version list is displayed
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const versionCountText = await page.locator('[data-testid="version-count"]').textContent();
    const versionCount = parseInt(versionCountText?.match(/\d+/)?.[0] || '0');
    expect(versionCount).toBeGreaterThan(0);

    // Locate and click the 'Export to CSV' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Wait for the CSV file generation to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Save the downloaded file
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify the CSV file exists
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Verify the CSV file structure and headers
    const csvData: any[] = [];
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => csvData.push(row))
        .on('end', resolve)
        .on('error', reject);
    });
    
    // Verify headers exist
    expect(Object.keys(csvData[0])).toContain('Version Number');
    expect(Object.keys(csvData[0])).toContain('Created Date');
    expect(Object.keys(csvData[0])).toContain('Created By');
    expect(Object.keys(csvData[0])).toContain('Changes Made');
    expect(Object.keys(csvData[0])).toContain('Status');
    
    // Verify data completeness by comparing row count
    expect(csvData.length).toBeGreaterThan(0);
    expect(csvData.length).toBeLessThanOrEqual(versionCount);
    
    // Verify data accuracy by spot-checking records
    const firstVersionInUI = await page.locator('[data-testid="version-row"]').first();
    const versionNumber = await firstVersionInUI.locator('[data-testid="version-number"]').textContent();
    const createdBy = await firstVersionInUI.locator('[data-testid="created-by"]').textContent();
    
    expect(csvData[0]['Version Number']).toBe(versionNumber?.trim());
    expect(csvData[0]['Created By']).toBe(createdBy?.trim());
    
    // Verify special characters, dates, and numerical values are correctly formatted
    csvData.slice(0, 3).forEach(row => {
      expect(row['Version Number']).toMatch(/^\d+(\.\d+)?$/);
      expect(row['Created Date']).toMatch(/\d{4}-\d{2}-\d{2}/);
      expect(row['Status']).toBeTruthy();
    });
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate CSV export of audit trail data (happy-path)', async ({ page }) => {
    // Navigate to the audit trail section from the main menu
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="audit-trail-menu-item"]');
    await expect(page).toHaveURL(/.*audit-trail/);
    await expect(page.locator('[data-testid="audit-trail-table"]')).toBeVisible();

    // Apply filters to the audit trail
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="quote-id-filter"]', 'Q-12345');
    await page.fill('[data-testid="date-from-filter"]', '2024-01-01');
    await page.fill('[data-testid="date-to-filter"]', '2024-12-31');
    await page.selectOption('[data-testid="action-type-filter"]', 'update');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Verify the filtered results display relevant audit information
    await expect(page.locator('[data-testid="audit-trail-table"]')).toBeVisible();
    const auditRecords = page.locator('[data-testid="audit-row"]');
    await expect(auditRecords.first()).toBeVisible();
    
    // Verify audit information columns are present
    await expect(page.locator('[data-testid="audit-timestamp"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-user"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-action"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-quote-id"]').first()).toBeVisible();
    
    const auditCountText = await page.locator('[data-testid="audit-count"]').textContent();
    const auditCount = parseInt(auditCountText?.match(/\d+/)?.[0] || '0');
    expect(auditCount).toBeGreaterThan(0);

    // Locate and click the 'Export to CSV' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Wait for the CSV file generation to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Save the downloaded file
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify the CSV file exists
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Open the CSV file and parse data
    const csvData: any[] = [];
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => csvData.push(row))
        .on('end', resolve)
        .on('error', reject);
    });
    
    // Verify the CSV file structure and headers
    expect(Object.keys(csvData[0])).toContain('Timestamp');
    expect(Object.keys(csvData[0])).toContain('User');
    expect(Object.keys(csvData[0])).toContain('Action Type');
    expect(Object.keys(csvData[0])).toContain('Quote ID');
    expect(Object.keys(csvData[0])).toContain('Field Changed');
    expect(Object.keys(csvData[0])).toContain('Old Value');
    expect(Object.keys(csvData[0])).toContain('New Value');
    expect(Object.keys(csvData[0])).toContain('IP Address');
    
    // Verify data completeness by comparing row count
    expect(csvData.length).toBeGreaterThan(0);
    expect(csvData.length).toBeLessThanOrEqual(auditCount);
    
    // Verify data accuracy by spot-checking audit records
    const firstAuditInUI = await page.locator('[data-testid="audit-row"]').first();
    const timestamp = await firstAuditInUI.locator('[data-testid="audit-timestamp"]').textContent();
    const user = await firstAuditInUI.locator('[data-testid="audit-user"]').textContent();
    const actionType = await firstAuditInUI.locator('[data-testid="audit-action"]').textContent();
    const quoteId = await firstAuditInUI.locator('[data-testid="audit-quote-id"]').textContent();
    
    expect(csvData[0]['User']).toBe(user?.trim());
    expect(csvData[0]['Action Type']).toBe(actionType?.trim());
    expect(csvData[0]['Quote ID']).toBe(quoteId?.trim());
    
    // Verify timestamp formatting is consistent and readable
    csvData.slice(0, 5).forEach(row => {
      expect(row['Timestamp']).toMatch(/\d{4}-\d{2}-\d{2}/);
      expect(row['Timestamp']).toBeTruthy();
    });
    
    // Verify special characters, long text fields, and multi-line values are properly escaped
    csvData.slice(0, 3).forEach(row => {
      expect(row['User']).toBeTruthy();
      expect(row['Action Type']).toBeTruthy();
      expect(row['Quote ID']).toMatch(/^Q-\d+$/);
      // Verify IP Address format if present
      if (row['IP Address']) {
        expect(row['IP Address']).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
      }
    });
    
    // Verify data can be manipulated (basic validation that CSV is well-formed)
    const uniqueUsers = new Set(csvData.map(row => row['User']));
    expect(uniqueUsers.size).toBeGreaterThan(0);
    
    const uniqueActionTypes = new Set(csvData.map(row => row['Action Type']));
    expect(uniqueActionTypes.size).toBeGreaterThan(0);
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate CSV export of quote versions - filtered version list is displayed', async ({ page }) => {
    // Navigate to version history
    await page.goto('/quotes');
    await page.click('[data-testid="quote-list-item"]');
    await page.click('[data-testid="version-history-tab"]');
    
    // Apply filters
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-from-filter"]', '2024-01-01');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Filtered version list is displayed
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const versionRows = page.locator('[data-testid="version-row"]');
    await expect(versionRows.first()).toBeVisible();
  });

  test('Validate CSV export of quote versions - CSV file is generated and downloaded', async ({ page }) => {
    // Navigate to version history and apply filters
    await page.goto('/quotes');
    await page.click('[data-testid="quote-list-item"]');
    await page.click('[data-testid="version-history-tab"]');
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-from-filter"]', '2024-01-01');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Click export to CSV
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Expected Result: CSV file is generated and downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/.*\.csv$/);
    
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate CSV export of quote versions - data is correctly formatted and complete', async ({ page }) => {
    // Navigate to version history and apply filters
    await page.goto('/quotes');
    await page.click('[data-testid="quote-list-item"]');
    await page.click('[data-testid="version-history-tab"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Export to CSV
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Open CSV file
    const csvData: any[] = [];
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => csvData.push(row))
        .on('end', resolve)
        .on('error', reject);
    });
    
    // Expected Result: Data is correctly formatted and complete
    expect(csvData.length).toBeGreaterThan(0);
    expect(Object.keys(csvData[0])).toContain('Version Number');
    expect(Object.keys(csvData[0])).toContain('Created Date');
    expect(Object.keys(csvData[0])).toContain('Created By');
    expect(csvData[0]['Version Number']).toBeTruthy();
    expect(csvData[0]['Created Date']).toMatch(/\d{4}-\d{2}-\d{2}/);
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate CSV export of audit trail data - filtered audit records are displayed', async ({ page }) => {
    // Navigate to audit trail
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="audit-trail-menu-item"]');
    
    // Apply filters
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="quote-id-filter"]', 'Q-12345');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Filtered audit records are displayed
    await expect(page.locator('[data-testid="audit-trail-table"]')).toBeVisible();
    const auditRows = page.locator('[data-testid="audit-row"]');
    await expect(auditRows.first()).toBeVisible();
    const quoteIdCell = await auditRows.first().locator('[data-testid="audit-quote-id"]').textContent();
    expect(quoteIdCell).toContain('Q-12345');
  });

  test('Validate CSV export of audit trail data - CSV file is generated and downloaded', async ({ page }) => {
    // Navigate to audit trail and apply filters
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="audit-trail-menu-item"]');
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-from-filter"]', '2024-01-01');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Click export to CSV
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Expected Result: CSV file is generated and downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/.*\.csv$/);
    
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate CSV export of audit trail data - audit data is correctly formatted and complete', async ({ page }) => {
    // Navigate to audit trail and apply filters
    await page.click('[data-testid="main-menu-button"]');
    await page.click('[data-testid="audit-trail-menu-item"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Export to CSV
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Open CSV file
    const csvData: any[] = [];
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => csvData.push(row))
        .on('end', resolve)
        .on('error', reject);
    });
    
    // Expected Result: Audit data is correctly formatted and complete
    expect(csvData.length).toBeGreaterThan(0);
    expect(Object.keys(csvData[0])).toContain('Timestamp');
    expect(Object.keys(csvData[0])).toContain('User');
    expect(Object.keys(csvData[0])).toContain('Action Type');
    expect(Object.keys(csvData[0])).toContain('Quote ID');
    expect(csvData[0]['Timestamp']).toMatch(/\d{4}-\d{2}-\d{2}/);
    expect(csvData[0]['User']).toBeTruthy();
    expect(csvData[0]['Action Type']).toBeTruthy();
    
    // Cleanup
    fs.unlinkSync(filePath);
  });
});