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
    const currentDate = new Date();
    const startDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="team-filter"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    await page.click('[data-testid="project-filter"]');
    await page.click('[data-testid="project-option-alpha"]');
    
    // Verify filters are accepted without errors
    await expect(page.locator('[data-testid="filter-error"]')).not.toBeVisible();

    // Step 3: Submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report is generated and displayed within 5 seconds
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    expect(generationTime).toBeLessThan(5000);
    
    // Verify report contains data
    await expect(page.locator('[data-testid="report-row"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-timeline"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-resource-assignments"]')).toBeVisible();
  });

  test('Export schedule report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate schedule report with filters
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();
    
    const currentDate = new Date();
    const startDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="team-filter"]');
    await page.click('[data-testid="team-option-engineering"]');
    await page.click('[data-testid="project-filter"]');
    await page.click('[data-testid="project-option-alpha"]');
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    // Capture on-screen report data for verification
    const reportData = await page.locator('[data-testid="schedule-report-table"]').textContent();
    
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
    
    // Verify PDF file size is greater than 0
    const pdfStats = fs.statSync(pdfPath!);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Step 3: Click export to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel file is downloaded
    const excelFilename = excelDownload.suggestedFilename();
    expect(excelFilename).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    expect(fs.existsSync(excelPath!)).toBeTruthy();
    
    // Verify Excel file size is greater than 0
    const excelStats = fs.statSync(excelPath!);
    expect(excelStats.size).toBeGreaterThan(0);
  });

  test('Verify real-time update of schedule report', async ({ page, context }) => {
    // Step 1: Open schedule report for a specific project
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-ui"]')).toBeVisible();
    
    const currentDate = new Date();
    const startDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.click('[data-testid="project-filter"]');
    await page.click('[data-testid="project-option-alpha"]');
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    
    // Step 2: Note current values displayed in the report
    const initialActivityDate = await page.locator('[data-testid="activity-date-1"]').textContent();
    const initialResourceName = await page.locator('[data-testid="resource-name-1"]').textContent();
    const initialTimeline = await page.locator('[data-testid="timeline-milestone-1"]').textContent();
    
    // Step 3: Update schedule data in backend using API
    const apiContext = await context.request;
    const updateResponse = await apiContext.put('/api/schedule/update', {
      data: {
        projectId: 'alpha',
        activityId: 1,
        activityDate: '2024-02-15',
        resourceName: 'John Smith (Updated)',
        timelineMilestone: 'Phase 2 Complete (Updated)'
      }
    });
    
    expect(updateResponse.ok()).toBeTruthy();
    
    // Step 4: Wait up to 10 seconds and monitor for automatic updates
    await page.waitForTimeout(1000); // Allow time for real-time update to propagate
    
    // Step 5: Verify updated data is reflected in the report
    await expect(page.locator('[data-testid="activity-date-1"]')).not.toHaveText(initialActivityDate!, { timeout: 10000 });
    
    const updatedActivityDate = await page.locator('[data-testid="activity-date-1"]').textContent();
    const updatedResourceName = await page.locator('[data-testid="resource-name-1"]').textContent();
    const updatedTimeline = await page.locator('[data-testid="timeline-milestone-1"]').textContent();
    
    // Verify the changes match backend updates
    expect(updatedActivityDate).toContain('2024-02-15');
    expect(updatedResourceName).toContain('John Smith (Updated)');
    expect(updatedTimeline).toContain('Phase 2 Complete (Updated)');
    
    // Verify that unchanged elements remain the same
    const unchangedElement = await page.locator('[data-testid="project-name"]').textContent();
    expect(unchangedElement).toContain('Project Alpha');
  });
});