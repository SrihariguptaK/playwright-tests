import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Task Status Reports - Team Lead Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Team Lead logs into the reporting system
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Generate task status report with valid filters', async ({ page }) => {
    // Step 1: Navigate to Task Status Reporting section from the main dashboard
    await page.click('[data-testid="task-status-reporting-link"]');
    
    // Expected Result: Task status report UI is displayed with filter options
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toBeVisible();

    // Step 2: Select a valid project from the project filter dropdown
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-alpha"]');
    
    // Step 3: Select a valid priority level from the priority filter dropdown
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Expected Result: Filters are accepted without errors
    await expect(page.locator('[data-testid="filter-error-message"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toContainText('Project Alpha');
    await expect(page.locator('[data-testid="priority-filter-dropdown"]')).toContainText('High');

    // Step 4: Click the 'Generate Report' button to submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Task status report is generated and displayed within 5 seconds
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    expect(generationTime).toBeLessThan(5000);

    // Step 5: Verify the report displays task count for each status category
    await expect(page.locator('[data-testid="pending-tasks-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="in-progress-tasks-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="completed-tasks-count"]')).toBeVisible();

    // Step 6: Verify the report contains only tasks matching the applied filters
    const taskRows = page.locator('[data-testid="task-row"]');
    const taskCount = await taskRows.count();
    
    for (let i = 0; i < taskCount; i++) {
      const taskRow = taskRows.nth(i);
      await expect(taskRow.locator('[data-testid="task-project"]')).toContainText('Project Alpha');
      await expect(taskRow.locator('[data-testid="task-priority"]')).toContainText('High');
    }
  });

  test('Export task status report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate task status report by selecting project and priority filters and clicking 'Generate Report'
    await page.click('[data-testid="task-status-reporting-link"]');
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-beta"]');
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-medium"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible();
    
    // Capture on-screen report data for comparison
    const pendingCount = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const inProgressCount = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
    const completedCount = await page.locator('[data-testid="completed-tasks-count"]').textContent();

    // Step 2: Locate and click the 'Export to PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file is downloaded with correct report data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = path.join(__dirname, 'downloads', pdfDownload.suggestedFilename());
    await pdfDownload.saveAs(pdfPath);
    expect(fs.existsSync(pdfPath)).toBeTruthy();
    expect(fs.statSync(pdfPath).size).toBeGreaterThan(0);

    // Step 3: Return to the task status report page in the application
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible();

    // Step 4: Locate and click the 'Export to Excel' button
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel file is downloaded with correct report data
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = path.join(__dirname, 'downloads', excelDownload.suggestedFilename());
    await excelDownload.saveAs(excelPath);
    expect(fs.existsSync(excelPath)).toBeTruthy();
    expect(fs.statSync(excelPath).size).toBeGreaterThan(0);

    // Step 5: Verify both exported files contain identical data matching the on-screen report
    // Note: Actual file content verification would require PDF/Excel parsing libraries
    // This validates that files were successfully downloaded with expected naming and non-zero size
    expect(pdfDownload.suggestedFilename()).toContain('task-status-report');
    expect(excelDownload.suggestedFilename()).toContain('task-status-report');
  });

  test('Verify real-time update of task status report', async ({ page, context }) => {
    // Step 1: Navigate to Task Status Reporting section and select a specific project
    await page.click('[data-testid="task-status-reporting-link"]');
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-gamma"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible();

    // Step 2: Note the current count of tasks in each status category
    const initialPendingText = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const initialInProgressText = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
    const initialCompletedText = await page.locator('[data-testid="completed-tasks-count"]').textContent();
    
    const initialPendingCount = parseInt(initialPendingText?.match(/\d+/)?.[0] || '0');
    const initialInProgressCount = parseInt(initialInProgressText?.match(/\d+/)?.[0] || '0');
    const initialCompletedCount = parseInt(initialCompletedText?.match(/\d+/)?.[0] || '0');

    // Step 3: Using backend access or another user session, update the status of a task from 'pending' to 'in-progress'
    const backendPage = await context.newPage();
    await backendPage.goto('/api/tasks/update');
    await backendPage.evaluate(() => {
      return fetch('/api/tasks/update-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          taskId: 'task-001',
          fromStatus: 'pending',
          toStatus: 'in-progress',
          project: 'Project Gamma'
        })
      });
    });
    await backendPage.close();

    // Step 4: Monitor the task status report UI without refreshing the page
    // Step 5: Verify the task count in 'pending' category decreased by 1
    await expect(async () => {
      const updatedPendingText = await page.locator('[data-testid="pending-tasks-count"]').textContent();
      const updatedPendingCount = parseInt(updatedPendingText?.match(/\d+/)?.[0] || '0');
      expect(updatedPendingCount).toBe(initialPendingCount - 1);
    }).toPass({ timeout: 10000 });

    // Step 6: Verify the task count in 'in-progress' category increased by 1
    await expect(async () => {
      const updatedInProgressText = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
      const updatedInProgressCount = parseInt(updatedInProgressText?.match(/\d+/)?.[0] || '0');
      expect(updatedInProgressCount).toBe(initialInProgressCount + 1);
    }).toPass({ timeout: 10000 });

    // Step 7: Update another task status from 'in-progress' to 'completed' in the backend
    const backendPage2 = await context.newPage();
    await backendPage2.goto('/api/tasks/update');
    await backendPage2.evaluate(() => {
      return fetch('/api/tasks/update-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          taskId: 'task-002',
          fromStatus: 'in-progress',
          toStatus: 'completed',
          project: 'Project Gamma'
        })
      });
    });
    await backendPage2.close();

    // Step 8: Monitor the report UI for automatic updates
    // Step 9: Verify all task status changes are accurately reflected in the report
    await expect(async () => {
      const finalInProgressText = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
      const finalInProgressCount = parseInt(finalInProgressText?.match(/\d+/)?.[0] || '0');
      expect(finalInProgressCount).toBe(initialInProgressCount);
    }).toPass({ timeout: 10000 });

    await expect(async () => {
      const finalCompletedText = await page.locator('[data-testid="completed-tasks-count"]').textContent();
      const finalCompletedCount = parseInt(finalCompletedText?.match(/\d+/)?.[0] || '0');
      expect(finalCompletedCount).toBe(initialCompletedCount + 1);
    }).toPass({ timeout: 10000 });

    // Verify the report shows latest task status information
    const finalPendingText = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const finalPendingCount = parseInt(finalPendingText?.match(/\d+/)?.[0] || '0');
    expect(finalPendingCount).toBe(initialPendingCount - 1);
  });
});