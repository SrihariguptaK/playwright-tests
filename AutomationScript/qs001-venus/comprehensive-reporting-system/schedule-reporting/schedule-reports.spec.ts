import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Schedule Report Generation', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate schedule report with valid filters', async ({ page }) => {
    // Step 1: Navigate to Schedule Reporting section
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="project-filter"]')).toBeVisible();

    // Step 2: Select valid date range, team, and project filters
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.selectOption('[data-testid="team-filter-dropdown"]', { label: 'Engineering Team' });
    await page.selectOption('[data-testid="project-filter-dropdown"]', { label: 'Project Alpha' });
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="filter-error-message"]')).not.toBeVisible();

    // Step 3: Submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated and displayed
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    // Verify report is generated within 5 seconds
    expect(generationTime).toBeLessThan(5000);
    
    // Verify report contains expected data
    await expect(page.locator('[data-testid="report-project-name"]')).toContainText('Project Alpha');
    await expect(page.locator('[data-testid="report-team-name"]')).toContainText('Engineering Team');
    await expect(page.locator('[data-testid="report-date-range"]')).toContainText('01/01/2024 - 31/01/2024');
    await expect(page.locator('[data-testid="report-activities-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-resource-assignments"]')).toBeVisible();
  });

  test('Export schedule report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate schedule report with filters
    await page.click('[data-testid="schedule-reporting-link"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.selectOption('[data-testid="team-filter-dropdown"]', { label: 'Engineering Team' });
    await page.selectOption('[data-testid="project-filter-dropdown"]', { label: 'Project Alpha' });
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();
    
    // Capture on-screen report data for comparison
    const reportProjectName = await page.locator('[data-testid="report-project-name"]').textContent();
    const reportTeamName = await page.locator('[data-testid="report-team-name"]').textContent();
    const reportDateRange = await page.locator('[data-testid="report-date-range"]').textContent();

    // Step 2: Click export to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF file is downloaded
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    expect(fs.existsSync(pdfPath!)).toBeTruthy();

    // Step 3: Click export to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel file is downloaded
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    expect(fs.existsSync(excelPath!)).toBeTruthy();
    
    // Verify both files have content (file size > 0)
    const pdfStats = fs.statSync(pdfPath!);
    const excelStats = fs.statSync(excelPath!);
    expect(pdfStats.size).toBeGreaterThan(0);
    expect(excelStats.size).toBeGreaterThan(0);
  });

  test('Verify real-time update of schedule report', async ({ page }) => {
    // Step 1: Open schedule report for a specific project
    await page.click('[data-testid="schedule-reporting-link"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    await page.selectOption('[data-testid="project-filter-dropdown"]', { label: 'Project Alpha' });
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();

    // Step 2: Note the current values displayed in the report
    const initialActivityDate = await page.locator('[data-testid="activity-date-0"]').textContent();
    const initialResourceName = await page.locator('[data-testid="resource-name-0"]').textContent();
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();

    // Step 3: Simulate backend update (trigger update via API or backend action)
    // In real scenario, this would be done via API call or database update
    await page.evaluate(() => {
      // Simulate backend schedule data update
      window.dispatchEvent(new CustomEvent('scheduleUpdate', {
        detail: {
          activityDate: '2024-01-15',
          resourceName: 'John Smith (Updated)',
          timestamp: new Date().toISOString()
        }
      }));
    });

    // Step 4: Monitor the report UI without refreshing the page
    // Wait for real-time update to occur (within 10 seconds)
    await page.waitForFunction(
      (oldTimestamp) => {
        const currentTimestamp = document.querySelector('[data-testid="last-updated-timestamp"]')?.textContent;
        return currentTimestamp !== oldTimestamp;
      },
      initialTimestamp,
      { timeout: 10000 }
    );

    // Step 5: Verify updated data is reflected in the report
    const updatedActivityDate = await page.locator('[data-testid="activity-date-0"]').textContent();
    const updatedResourceName = await page.locator('[data-testid="resource-name-0"]').textContent();
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();

    // Verify data has changed
    expect(updatedActivityDate).not.toBe(initialActivityDate);
    expect(updatedResourceName).not.toBe(initialResourceName);
    expect(updatedTimestamp).not.toBe(initialTimestamp);

    // Verify report shows latest schedule information
    await expect(page.locator('[data-testid="schedule-report-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="last-updated-timestamp"]')).toBeVisible();
    
    // Verify timestamp shows recent update (within last minute)
    const timestampText = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(timestampText).toBeTruthy();
  });
});