import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Attendance Reports - Story 8', () => {
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
    await page.waitForSelector('[data-testid="attendance-dashboard"]');
  });

  test('Validate export of attendance reports in CSV format', async ({ page }) => {
    // Step 1: Apply filters on dashboard
    await page.click('[data-testid="filter-button"]');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.selectOption('[data-testid="department-filter"]', 'Engineering');
    await page.selectOption('[data-testid="status-filter"]', 'Present');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for filtered data to load
    await page.waitForSelector('[data-testid="attendance-table"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Filtered data is displayed
    const filteredRows = await page.locator('[data-testid="attendance-row"]').count();
    expect(filteredRows).toBeGreaterThan(0);
    
    // Get the record count from dashboard
    const recordCountText = await page.locator('[data-testid="record-count"]').textContent();
    const dashboardRecordCount = parseInt(recordCountText?.match(/\d+/)?.[0] || '0');
    
    // Step 2: Select CSV export and initiate export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    // Expected Result: CSV file is generated and downloaded
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.csv');
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Step 3: Open CSV file and verify contents
    // Expected Result: File contains filtered attendance data accurately
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    const csvContent = fs.readFileSync(filePath, 'utf-8');
    const csvLines = csvContent.split('\n').filter(line => line.trim() !== '');
    const csvDataRows = csvLines.length - 1; // Exclude header row
    
    // Verify CSV contains expected columns
    const headerRow = csvLines[0];
    expect(headerRow).toContain('employee name');
    expect(headerRow).toContain('date');
    expect(headerRow).toContain('time in');
    expect(headerRow).toContain('time out');
    expect(headerRow).toContain('status');
    
    // Verify data count matches dashboard
    expect(csvDataRows).toBe(dashboardRecordCount);
    
    // Verify filtered data is present
    expect(csvContent).toContain('Engineering');
    expect(csvContent).toContain('Present');
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Validate export completion notification', async ({ page }) => {
    // Step 1: Initiate export
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-excel-option"]');
    
    // Expected Result: Export progress is displayed
    await expect(page.locator('[data-testid="export-progress"]')).toBeVisible();
    const progressText = await page.locator('[data-testid="export-progress"]').textContent();
    expect(progressText).toMatch(/exporting|processing|generating/i);
    
    // Step 2: Wait for export to complete
    const downloadPromise = page.waitForEvent('download', { timeout: 35000 });
    const download = await downloadPromise;
    
    // Expected Result: System notifies manager of successful export
    await expect(page.locator('[data-testid="notification-message"]')).toBeVisible({ timeout: 5000 });
    const notificationText = await page.locator('[data-testid="notification-message"]').textContent();
    expect(notificationText).toMatch(/export.*complete|export.*success|successfully exported/i);
    
    // Verify notification contains relevant information
    expect(notificationText).toBeTruthy();
    
    // Verify exported file is available
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test('Test export performance', async ({ page }) => {
    // Step 1: Apply filters to select a large dataset
    await page.click('[data-testid="filter-button"]');
    
    // Select 6-12 months date range
    const endDate = new Date();
    const startDate = new Date();
    startDate.setMonth(startDate.getMonth() - 12);
    
    await page.fill('[data-testid="date-range-start"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-range-end"]', endDate.toISOString().split('T')[0]);
    
    // Select all departments
    await page.selectOption('[data-testid="department-filter"]', 'All');
    
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForLoadState('networkidle');
    
    // Step 2: Note the total number of records to be exported
    const recordCountText = await page.locator('[data-testid="record-count"]').textContent();
    const totalRecords = parseInt(recordCountText?.match(/\d+/)?.[0] || '0');
    expect(totalRecords).toBeGreaterThan(100); // Ensure it's a large dataset
    
    // Step 3: Start timer and initiate export
    const startTime = Date.now();
    
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Step 4: Monitor export progress and wait for completion
    await expect(page.locator('[data-testid="export-progress"]')).toBeVisible();
    
    const downloadPromise = page.waitForEvent('download', { timeout: 35000 });
    const download = await downloadPromise;
    
    // Step 5: Stop timer when export completes
    const endTime = Date.now();
    const exportDuration = (endTime - startTime) / 1000; // Convert to seconds
    
    // Expected Result: Export completes within 30 seconds
    expect(exportDuration).toBeLessThanOrEqual(30);
    
    // Step 6: Verify the exported file is complete and not corrupted
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    expect(fs.existsSync(filePath)).toBeTruthy();
    const fileStats = fs.statSync(filePath);
    expect(fileStats.size).toBeGreaterThan(0); // File is not empty
    
    // Verify file format
    expect(download.suggestedFilename()).toMatch(/\.pdf$/i);
    
    // Verify completion notification
    await expect(page.locator('[data-testid="notification-message"]')).toBeVisible();
    const notificationText = await page.locator('[data-testid="notification-message"]').textContent();
    expect(notificationText).toMatch(/export.*complete|export.*success/i);
    
    // Cleanup
    fs.unlinkSync(filePath);
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Ensure downloads directory exists
    if (!fs.existsSync(downloadsPath)) {
      fs.mkdirSync(downloadsPath, { recursive: true });
    }
  });
});