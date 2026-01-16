import { test, expect } from '@playwright/test';

test.describe('Task Status Reports - Overdue Task Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate overdue task detection in task status reports', async ({ page }) => {
    // Navigate to task status reporting module
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');
    await expect(page.locator('[data-testid="task-status-report-page"]')).toBeVisible();

    // Select a project that contains tasks with overdue dates from the project filter dropdown
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-overdue-project"]');
    await expect(page.locator('[data-testid="project-filter-dropdown"]')).toContainText('Overdue Project');

    // Click 'Generate Report' button to generate task status report with overdue tasks
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 15000 });
    await expect(page.locator('[data-testid="report-generated-message"]')).toBeVisible();

    // Review the generated report and identify tasks marked as overdue
    const overdueTaskRows = page.locator('[data-testid="task-row"][data-status="overdue"]');
    await expect(overdueTaskRows.first()).toBeVisible();

    // Verify that all tasks with due dates in the past are flagged as overdue
    const overdueCount = await overdueTaskRows.count();
    expect(overdueCount).toBeGreaterThan(0);
    
    // Verify overdue tasks have visual highlighting
    await expect(overdueTaskRows.first()).toHaveClass(/overdue-highlight/);

    // Apply additional filter to show only overdue tasks by project
    await page.click('[data-testid="filter-overdue-only-checkbox"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="report-container"]');

    // Filter report by a specific assignee who has overdue tasks
    await page.click('[data-testid="assignee-filter-dropdown"]');
    await page.click('[data-testid="assignee-option-john-doe"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="report-container"]');

    // Verify overdue task count matches the filtered results
    const filteredOverdueCount = await page.locator('[data-testid="task-row"][data-status="overdue"]').count();
    const displayedCount = await page.locator('[data-testid="overdue-task-count"]').textContent();
    expect(filteredOverdueCount.toString()).toBe(displayedCount?.trim());

    // Verify filtered report shows overdue tasks for selected project
    const projectCells = page.locator('[data-testid="task-row"] [data-testid="project-cell"]');
    const projectCount = await projectCells.count();
    for (let i = 0; i < projectCount; i++) {
      await expect(projectCells.nth(i)).toContainText('Overdue Project');
    }
  });

  test('Verify export of task status reports with overdue task highlights', async ({ page }) => {
    // Navigate to task status reporting module
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');
    await expect(page.locator('[data-testid="task-status-report-page"]')).toBeVisible();

    // Select a project with overdue tasks and apply relevant filters
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-overdue-project"]');
    await page.click('[data-testid="filter-overdue-only-checkbox"]');

    // Click 'Generate Report' button to generate task status report with overdue highlights
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 15000 });

    // Verify that overdue tasks are visually distinguished in the on-screen report
    const overdueTaskRows = page.locator('[data-testid="task-row"][data-status="overdue"]');
    await expect(overdueTaskRows.first()).toBeVisible();
    await expect(overdueTaskRows.first()).toHaveClass(/overdue-highlight/);
    
    // Store overdue task data for comparison
    const onScreenOverdueTasks = await overdueTaskRows.count();
    const firstTaskName = await overdueTaskRows.first().locator('[data-testid="task-name"]').textContent();

    // Click 'Export to Excel' button to export the report
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    const downloadExcel = await downloadPromiseExcel;
    
    // Verify Excel file download
    expect(downloadExcel.suggestedFilename()).toContain('.xlsx');
    await downloadExcel.saveAs(`./downloads/${downloadExcel.suggestedFilename()}`);

    // Verify export success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Excel');

    // Return to the report page and click 'Export to PDF' button
    await page.waitForTimeout(1000);
    const downloadPromisePdf = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPdf = await downloadPromisePdf;
    
    // Verify PDF file download
    expect(downloadPdf.suggestedFilename()).toContain('.pdf');
    await downloadPdf.saveAs(`./downloads/${downloadPdf.suggestedFilename()}`);

    // Verify export success message for PDF
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF');

    // Verify both exports completed successfully
    const exportHistory = page.locator('[data-testid="export-history-item"]');
    await expect(exportHistory).toHaveCount(2);
  });

  test('Validate overdue task detection accuracy - 100% detection rate', async ({ page }) => {
    // Navigate to task status reporting module
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');

    // Generate report with all projects
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-all-projects"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 15000 });

    // Get all task rows
    const allTaskRows = page.locator('[data-testid="task-row"]');
    const totalTasks = await allTaskRows.count();

    // Verify each task's overdue status matches its due date
    for (let i = 0; i < totalTasks; i++) {
      const taskRow = allTaskRows.nth(i);
      const dueDateText = await taskRow.locator('[data-testid="due-date"]').textContent();
      const isMarkedOverdue = await taskRow.getAttribute('data-status') === 'overdue';
      
      if (dueDateText) {
        const dueDate = new Date(dueDateText.trim());
        const today = new Date();
        const shouldBeOverdue = dueDate < today;
        
        // Verify overdue flag matches actual due date status
        expect(isMarkedOverdue).toBe(shouldBeOverdue);
      }
    }
  });

  test('Verify report generation performance within 15 seconds SLA', async ({ page }) => {
    // Navigate to task status reporting module
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');

    // Select project with large dataset
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option-large-project"]');

    // Measure report generation time
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-container"]', { timeout: 15000 });
    const endTime = Date.now();
    
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generated within 15 seconds SLA
    expect(generationTime).toBeLessThanOrEqual(15);
    
    // Verify report contains data
    const taskRows = page.locator('[data-testid="task-row"]');
    await expect(taskRows.first()).toBeVisible();
  });
});