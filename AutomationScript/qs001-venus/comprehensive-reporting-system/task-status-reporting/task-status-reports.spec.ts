import { test, expect } from '@playwright/test';

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
    // Step 1: Navigate to Task Status Reporting section
    await page.click('[data-testid="task-status-reporting-link"]');
    
    // Expected Result: Task status report UI is displayed with filter options
    await expect(page.locator('[data-testid="task-status-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="project-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="priority-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter"]')).toBeVisible();
    
    // Step 2: Select valid project and priority filters
    await page.selectOption('[data-testid="project-filter"]', { label: 'Project Alpha' });
    await page.selectOption('[data-testid="priority-filter"]', { label: 'High' });
    
    // Expected Result: Filters are accepted without errors
    await expect(page.locator('[data-testid="filter-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="project-filter"]')).toHaveValue('project-alpha');
    await expect(page.locator('[data-testid="priority-filter"]')).toHaveValue('high');
    
    // Step 3: Submit report generation request
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Task status report is generated and displayed within 5 seconds
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    expect(generationTime).toBeLessThan(5000);
    
    // Verify report displays task count for each status category
    await expect(page.locator('[data-testid="pending-tasks-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="in-progress-tasks-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="completed-tasks-count"]')).toBeVisible();
    
    // Verify task counts are numeric values
    const pendingCount = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const inProgressCount = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
    const completedCount = await page.locator('[data-testid="completed-tasks-count"]').textContent();
    
    expect(Number(pendingCount)).toBeGreaterThanOrEqual(0);
    expect(Number(inProgressCount)).toBeGreaterThanOrEqual(0);
    expect(Number(completedCount)).toBeGreaterThanOrEqual(0);
  });

  test('Export task status report to PDF and Excel', async ({ page }) => {
    // Step 1: Generate task status report by selecting project and priority filters
    await page.click('[data-testid="task-status-reporting-link"]');
    await page.selectOption('[data-testid="project-filter"]', { label: 'Project Alpha' });
    await page.selectOption('[data-testid="priority-filter"]', { label: 'High' });
    await page.click('[data-testid="generate-report-button"]');
    
    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible();
    
    // Capture report data for verification
    const pendingCountText = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const inProgressCountText = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
    const completedCountText = await page.locator('[data-testid="completed-tasks-count"]').textContent();
    
    // Step 2: Click export to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Expected Result: PDF file is downloaded with correct report data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('task-status-report');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Step 3: Return to the task status report page and click export to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Expected Result: Excel file is downloaded with correct report data
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(excelDownload.suggestedFilename()).toContain('task-status-report');
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    
    // Verify both files were successfully downloaded
    expect(await pdfDownload.failure()).toBeNull();
    expect(await excelDownload.failure()).toBeNull();
  });

  test('Verify real-time update of task status report', async ({ page, context }) => {
    // Step 1: Navigate to Task Status Reporting section and select a specific project filter
    await page.click('[data-testid="task-status-reporting-link"]');
    await page.selectOption('[data-testid="project-filter"]', { label: 'Project Beta' });
    
    // Step 2: Click 'Generate Report' to open task status report for the selected project
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="task-status-report-results"]')).toBeVisible();
    
    // Step 3: Note the current count of tasks in each status category
    const initialPendingCount = await page.locator('[data-testid="pending-tasks-count"]').textContent();
    const initialInProgressCount = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
    const initialCompletedCount = await page.locator('[data-testid="completed-tasks-count"]').textContent();
    
    const initialPending = Number(initialPendingCount);
    const initialInProgress = Number(initialInProgressCount);
    const initialCompleted = Number(initialCompletedCount);
    
    // Step 4: Update a task status in the backend system
    // Simulate backend update by opening admin panel in new page
    const adminPage = await context.newPage();
    await adminPage.goto('/admin/tasks');
    await adminPage.fill('[data-testid="admin-username"]', 'admin@example.com');
    await adminPage.fill('[data-testid="admin-password"]', 'AdminPass123');
    await adminPage.click('[data-testid="admin-login-button"]');
    
    // Find a pending task and move it to in-progress
    await adminPage.click('[data-testid="pending-tasks-tab"]');
    await adminPage.waitForSelector('[data-testid="task-item"]');
    const firstTask = adminPage.locator('[data-testid="task-item"]').first();
    const taskId = await firstTask.getAttribute('data-task-id');
    await firstTask.click();
    await adminPage.selectOption('[data-testid="task-status-dropdown"]', { label: 'In Progress' });
    await adminPage.click('[data-testid="save-task-button"]');
    await expect(adminPage.locator('[data-testid="task-updated-message"]')).toBeVisible();
    
    // Step 5: Monitor the report UI for automatic updates without manual refresh
    // Wait for real-time update (within 10 seconds as per acceptance criteria)
    await page.waitForTimeout(2000); // Allow websocket/polling to trigger
    
    // Step 6: Verify the updated task statuses are reflected in the report by checking task counts
    await expect(async () => {
      const updatedPendingCount = await page.locator('[data-testid="pending-tasks-count"]').textContent();
      const updatedInProgressCount = await page.locator('[data-testid="in-progress-tasks-count"]').textContent();
      
      const updatedPending = Number(updatedPendingCount);
      const updatedInProgress = Number(updatedInProgressCount);
      
      // Pending should decrease by 1, In Progress should increase by 1
      expect(updatedPending).toBe(initialPending - 1);
      expect(updatedInProgress).toBe(initialInProgress + 1);
    }).toPass({ timeout: 10000 });
    
    // Step 7: Verify the specific task that was updated now appears in the correct status category
    await page.click('[data-testid="in-progress-tasks-section"]');
    await expect(page.locator(`[data-testid="task-${taskId}"]`)).toBeVisible();
    await expect(page.locator(`[data-testid="task-${taskId}-status"]`)).toHaveText('In Progress');
    
    // Verify task is no longer in pending section
    await page.click('[data-testid="pending-tasks-section"]');
    await expect(page.locator(`[data-testid="task-${taskId}"]`)).not.toBeVisible();
    
    // Cleanup
    await adminPage.close();
  });
});