import { test, expect } from '@playwright/test';

test.describe('Task Status Reports - Story 3', () => {
  test.beforeEach(async ({ page }) => {
    // Login as project manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'projectmanager@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate task status report generation with valid filters', async ({ page }) => {
    // Step 1: Navigate to task status reporting module
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');
    await expect(page.locator('[data-testid="task-status-report-ui"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Task Status Report');

    // Step 2: Select valid project and filters
    await page.selectOption('[data-testid="project-filter-dropdown"]', { label: 'Project Alpha' });
    await page.fill('[data-testid="start-date-picker"]', '2024-01-01');
    await page.fill('[data-testid="end-date-picker"]', '2024-12-31');
    await page.selectOption('[data-testid="team-filter-dropdown"]', { label: 'Development Team' });
    
    // Verify filters accepted without errors
    await expect(page.locator('[data-testid="filter-error-message"]')).not.toBeVisible();

    // Step 3: Request report generation
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="report-results-table"]', { timeout: 20000 });
    
    // Verify task status report is generated and displayed with correct data
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-task-name"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-assignee"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-status"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-progress-percentage"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="report-due-date"]').first()).toBeVisible();
    
    // Verify completion percentage is displayed
    const completionPercentage = await page.locator('[data-testid="overall-completion-percentage"]').textContent();
    expect(completionPercentage).toMatch(/\d+%/);
    
    // Verify overdue tasks section exists
    await expect(page.locator('[data-testid="overdue-tasks-section"]')).toBeVisible();
  });

  test('Verify export functionality for task status reports', async ({ page }) => {
    // Step 1: Generate task status report with filters
    await page.click('[data-testid="reports-menu"]');
    await page.click('[data-testid="task-status-reports-link"]');
    
    await page.selectOption('[data-testid="project-filter-dropdown"]', { label: 'Project Alpha' });
    await page.fill('[data-testid="start-date-picker"]', '2024-01-01');
    await page.fill('[data-testid="end-date-picker"]', '2024-12-31');
    await page.click('[data-testid="generate-report-button"]');
    
    await page.waitForSelector('[data-testid="report-results-table"]', { timeout: 20000 });
    await expect(page.locator('[data-testid="report-results-table"]')).toBeVisible();

    // Step 2: Export report to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel file is downloaded
    expect(excelDownload.suggestedFilename()).toContain('.xlsx');
    expect(excelDownload.suggestedFilename()).toContain('task_status_report');
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();

    // Step 3: Export report to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF file is downloaded with correct formatting
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('task_status_report');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Verify success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access task status reports', async ({ page }) => {
    // Logout from project manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 1: Login as non-project manager user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'developer@example.com');
    await page.fill('[data-testid="password-input"]', 'DevPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify access to task status reporting module is denied
    await page.click('[data-testid="reports-menu"]');
    
    // Verify task status reports menu option is not visible
    await expect(page.locator('[data-testid="task-status-reports-link"]')).not.toBeVisible();
    
    // Step 2: Attempt to access API endpoint directly
    const response = await page.request.get('/api/reports/taskstatus', {
      params: {
        project: 'Project Alpha',
        startDate: '2024-01-01',
        endDate: '2024-12-31'
      }
    });
    
    // Verify access forbidden response received
    expect(response.status()).toBe(403);
    
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/forbidden|unauthorized|access denied/i);
    
    // Attempt to navigate directly via URL
    await page.goto('/reports/task-status');
    
    // Verify user is redirected or sees access denied message
    const currentUrl = page.url();
    const accessDeniedVisible = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    
    expect(currentUrl.includes('/reports/task-status') === false || accessDeniedVisible).toBeTruthy();
    
    if (accessDeniedVisible) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    }
  });
});