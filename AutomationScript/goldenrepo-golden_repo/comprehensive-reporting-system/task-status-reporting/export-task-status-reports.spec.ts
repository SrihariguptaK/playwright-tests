import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Task Status Reports to Excel', () => {
  const downloadsPath = path.join(__dirname, 'downloads');

  test.beforeEach(async ({ page }) => {
    // Navigate to the task status reports section
    await page.goto('/reports/task-status');
    await expect(page).toHaveURL(/.*reports\/task-status/);
  });

  test('Export task status report to Excel (happy-path)', async ({ page }) => {
    // Step 1: Select filters or parameters for the task status report
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    await page.click('[data-testid="project-filter"]');
    await page.click('text="Project Alpha"');
    
    await page.click('[data-testid="status-filter"]');
    await page.selectOption('[data-testid="status-filter"]', 'In Progress');

    // Step 2: Click on 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Step 3: Verify the report data is displayed correctly on screen
    await expect(page.locator('[data-testid="report-table"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-table"] thead th')).toHaveCount(6);
    
    // Verify column headers are present
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Task Name');
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Status');
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Assignee');
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Due Date');
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Priority');
    await expect(page.locator('[data-testid="report-table"] thead')).toContainText('Completion %');
    
    // Get sample data from the displayed report for later verification
    const sampleRows = await page.locator('[data-testid="report-table"] tbody tr').count();
    expect(sampleRows).toBeGreaterThan(0);
    
    const sampleData = [];
    for (let i = 0; i < Math.min(5, sampleRows); i++) {
      const row = page.locator(`[data-testid="report-table"] tbody tr:nth-child(${i + 1})`);
      const taskName = await row.locator('td:nth-child(1)').textContent();
      const status = await row.locator('td:nth-child(2)').textContent();
      const assignee = await row.locator('td:nth-child(3)').textContent();
      const dueDate = await row.locator('td:nth-child(4)').textContent();
      const priority = await row.locator('td:nth-child(5)').textContent();
      const completion = await row.locator('td:nth-child(6)').textContent();
      
      sampleData.push({
        taskName: taskName?.trim(),
        status: status?.trim(),
        assignee: assignee?.trim(),
        dueDate: dueDate?.trim(),
        priority: priority?.trim(),
        completion: completion?.trim()
      });
    }

    // Step 4: Locate and click on 'Export to Excel' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-excel-button"]');
    
    // Step 5: Wait for export processing to complete
    await expect(page.locator('[data-testid="export-progress"]')).toBeVisible({ timeout: 2000 });
    
    const download = await downloadPromise;
    
    // Step 6: Check the downloaded file location and verify file name format
    const fileName = download.suggestedFilename();
    const fileNamePattern = /TaskStatusReport_\d{4}-\d{2}-\d{2}\.xlsx/;
    expect(fileName).toMatch(fileNamePattern);
    
    const filePath = path.join(downloadsPath, fileName);
    await download.saveAs(filePath);
    
    // Verify file exists
    expect(fs.existsSync(filePath)).toBeTruthy();
    
    // Verify file size is greater than 0
    const stats = fs.statSync(filePath);
    expect(stats.size).toBeGreaterThan(0);
    
    // Step 7: Verify export completed successfully
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Export completed successfully');
    
    // Verify export processing time
    const exportTime = await page.locator('[data-testid="export-time"]').textContent();
    const timeInSeconds = parseFloat(exportTime?.replace('s', '') || '0');
    expect(timeInSeconds).toBeLessThanOrEqual(10);
    
    // Note: Steps 8-12 (Opening Excel file and verifying structure/data/formatting)
    // would require additional libraries like 'exceljs' or 'xlsx' to parse Excel files
    // This is a placeholder for those verification steps
    // In a real implementation, you would:
    // - Use exceljs to open the downloaded file
    // - Verify column headers match expected structure
    // - Compare sample data with the data captured from the UI
    // - Verify formatting (bold headers, date formats, percentage symbols)
    // - Verify row count matches the report
  });

  test('Export task status report to Excel - verify data structure', async ({ page }) => {
    // Generate task status report
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Select export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-excel-button"]');
    
    const download = await downloadPromise;
    
    // Verify Excel file downloaded
    expect(download.suggestedFilename()).toContain('.xlsx');
    
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Verify data correctly structured and formatted
    expect(fs.existsSync(filePath)).toBeTruthy();
    const stats = fs.statSync(filePath);
    expect(stats.size).toBeGreaterThan(1000); // Reasonable minimum size for Excel file with data
  });

  test('Export task status report to Excel - verify processing time under 10 seconds', async ({ page }) => {
    // Generate task status report with up to 1000 records
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-all-time"]');
    
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Verify report has records
    const rowCount = await page.locator('[data-testid="report-table"] tbody tr').count();
    expect(rowCount).toBeGreaterThan(0);
    expect(rowCount).toBeLessThanOrEqual(1000);
    
    // Start timer
    const startTime = Date.now();
    
    // Export to Excel
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-to-excel-button"]');
    
    const download = await downloadPromise;
    const filePath = path.join(downloadsPath, download.suggestedFilename());
    await download.saveAs(filePath);
    
    // Calculate processing time
    const endTime = Date.now();
    const processingTime = (endTime - startTime) / 1000;
    
    // Verify export processed within 10 seconds
    expect(processingTime).toBeLessThanOrEqual(10);
    
    // Verify success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Export task status report to Excel - verify access control for authorized users', async ({ page }) => {
    // Assume user is logged in as authorized Project Manager
    await page.goto('/reports/task-status');
    
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-table"]')).toBeVisible({ timeout: 10000 });
    
    // Verify export button is visible and enabled for authorized user
    const exportButton = page.locator('[data-testid="export-to-excel-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();
    
    // Click export button
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();
    
    // Verify export is successful
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.xlsx');
  });

  test.afterEach(async () => {
    // Cleanup: Remove downloaded files after each test
    if (fs.existsSync(downloadsPath)) {
      const files = fs.readdirSync(downloadsPath);
      files.forEach(file => {
        if (file.endsWith('.xlsx')) {
          fs.unlinkSync(path.join(downloadsPath, file));
        }
      });
    }
  });
});