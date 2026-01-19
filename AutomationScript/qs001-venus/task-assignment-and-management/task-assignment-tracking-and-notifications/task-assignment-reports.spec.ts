import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Task Assignment Reports - Story 21', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate report generation with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to reports section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reports-menu-item"]');
    
    // Expected Result: Report filter form is displayed
    await expect(page.locator('[data-testid="report-filter-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-filter"]')).toBeVisible();

    // Step 2: Select filter criteria
    // Select date range (last 30 days)
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-option-30-days"]');
    
    // Select specific employee or team
    await page.click('[data-testid="employee-filter"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Doe');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Select priority level (High)
    await page.click('[data-testid="priority-filter"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Select status (In Progress)
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-option-in-progress"]');
    
    // Click Generate Report button
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is generated accurately and displayed
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Task Assignment Report');
    
    // Verify the accuracy of the generated report data
    const reportRows = page.locator('[data-testid="report-row"]');
    await expect(reportRows).not.toHaveCount(0);
    
    // Verify filters are applied correctly
    const firstRow = reportRows.first();
    await expect(firstRow.locator('[data-testid="task-priority"]')).toContainText('High');
    await expect(firstRow.locator('[data-testid="task-status"]')).toContainText('In Progress');
    
    // Store on-screen report data for comparison
    const onScreenData = await page.locator('[data-testid="report-results"]').textContent();

    // Step 3: Export report to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF export is successful
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', pdfDownload.suggestedFilename());
    await pdfDownload.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    
    // Verify PDF file size is reasonable (not empty)
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(1000);

    // Return to report view and export to Excel
    await page.waitForTimeout(1000);
    
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel export is successful and data is intact
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(__dirname, 'downloads', excelDownload.suggestedFilename());
    await excelDownload.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    
    // Verify Excel file size is reasonable (not empty)
    const excelStats = fs.statSync(excelPath);
    expect(excelStats.size).toBeGreaterThan(1000);
    
    // Verify export success messages
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Verify report scheduling functionality (happy-path)', async ({ page }) => {
    // Step 1: Navigate to reports section and select Schedule Report option
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reports-menu-item"]');
    await page.click('[data-testid="schedule-report-button"]');
    
    // Expected Result: Schedule report form is displayed
    await expect(page.locator('[data-testid="schedule-report-form"]')).toBeVisible();

    // Step 2: Configure the scheduled report
    // Select report type (task assignments)
    await page.click('[data-testid="report-type-select"]');
    await page.click('[data-testid="report-type-task-assignments"]');
    
    // Apply desired filters (all employees, all priorities)
    await page.click('[data-testid="schedule-employee-filter"]');
    await page.click('[data-testid="employee-option-all"]');
    
    await page.click('[data-testid="schedule-priority-filter"]');
    await page.click('[data-testid="priority-option-all"]');
    
    // Set frequency (weekly, every Monday at 9 AM)
    await page.click('[data-testid="frequency-select"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    
    await page.click('[data-testid="day-of-week-select"]');
    await page.click('[data-testid="day-option-monday"]');
    
    await page.fill('[data-testid="schedule-time-input"]', '09:00');
    
    // Specify delivery method (email)
    await page.click('[data-testid="delivery-method-select"]');
    await page.click('[data-testid="delivery-option-email"]');
    
    await page.fill('[data-testid="delivery-email-input"]', 'manager@example.com');
    
    // Give the schedule a name for identification
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Task Assignment Report');

    // Step 3: Click Save Schedule button
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Schedule is saved
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');

    // Step 4: Verify the scheduled report details in the scheduled reports list
    await page.click('[data-testid="view-scheduled-reports-link"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduledReport = page.locator('[data-testid="scheduled-report-item"]').filter({ hasText: 'Weekly Task Assignment Report' });
    await expect(scheduledReport).toBeVisible();
    await expect(scheduledReport.locator('[data-testid="schedule-frequency"]')).toContainText('Weekly');
    await expect(scheduledReport.locator('[data-testid="schedule-day"]')).toContainText('Monday');
    await expect(scheduledReport.locator('[data-testid="schedule-time"]')).toContainText('09:00');
    await expect(scheduledReport.locator('[data-testid="schedule-delivery"]')).toContainText('Email');
    
    // Step 5: Trigger the scheduled report manually if test environment allows
    await scheduledReport.locator('[data-testid="trigger-now-button"]').click();
    
    // Expected Result: Report is generated as per schedule
    await expect(page.locator('[data-testid="report-triggered-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="report-triggered-message"]')).toContainText('Report generation initiated');
    
    // Verify report delivery notification
    await page.waitForTimeout(2000);
    await expect(page.locator('[data-testid="delivery-confirmation"]')).toBeVisible({ timeout: 15000 });
  });

  test('Ensure report generation performance (boundary)', async ({ page }) => {
    const performanceResults: number[] = [];
    
    // Step 1: Navigate to reports section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reports-menu-item"]');
    await expect(page.locator('[data-testid="report-filter-form"]')).toBeVisible();

    // Step 2: Select filters representing typical report criteria
    // Last 30 days, all employees, all priorities and statuses
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-option-30-days"]');
    
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-all"]');
    
    await page.click('[data-testid="priority-filter"]');
    await page.click('[data-testid="priority-option-all"]');
    
    await page.click('[data-testid="status-filter"]');
    await page.click('[data-testid="status-option-all"]');

    // Step 3: Repeat report generation 3 times to measure performance
    for (let i = 1; i <= 3; i++) {
      // Start timer
      const startTime = Date.now();
      
      // Click Generate Report button
      await page.click('[data-testid="generate-report-button"]');
      
      // Wait for report to be fully displayed
      await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 10000 });
      await page.waitForLoadState('networkidle');
      
      // Stop timer
      const endTime = Date.now();
      const generationTime = (endTime - startTime) / 1000; // Convert to seconds
      performanceResults.push(generationTime);
      
      console.log(`Report generation attempt ${i}: ${generationTime} seconds`);
      
      // Expected Result: Report is generated within 5 seconds
      expect(generationTime).toBeLessThanOrEqual(5);
      
      // Step 4: Verify the completeness and accuracy of the generated report
      await expect(page.locator('[data-testid="report-title"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-row"]')).not.toHaveCount(0);
      
      // Verify report contains expected columns
      await expect(page.locator('[data-testid="report-header-task-name"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-header-assignee"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-header-priority"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-header-status"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-header-deadline"]')).toBeVisible();
      
      // Verify report summary statistics are displayed
      await expect(page.locator('[data-testid="report-total-tasks"]')).toBeVisible();
      await expect(page.locator('[data-testid="report-summary"]')).toBeVisible();
      
      // Wait before next iteration
      if (i < 3) {
        await page.waitForTimeout(1000);
        // Clear report to prepare for next generation
        await page.click('[data-testid="clear-report-button"]');
        await page.waitForTimeout(500);
      }
    }
    
    // Calculate average generation time
    const averageTime = performanceResults.reduce((a, b) => a + b, 0) / performanceResults.length;
    console.log(`Average report generation time: ${averageTime} seconds`);
    
    // Verify average performance meets requirement
    expect(averageTime).toBeLessThanOrEqual(5);
  });
});